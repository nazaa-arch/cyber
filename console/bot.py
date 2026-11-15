"""Bot Dalang (Bab 11): ringkasan satu layar untuk perwira jaga, bahasa Indonesia.

Tombol: "Setujui blokir", "Abaikan", "Buka konsol". Kanal dapat diganti
(kanal internal, Telegram). Kanal bawaan tidak butuh jaringan.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import pathlib
import threading
import time
import urllib.request

log = logging.getLogger("wayang.bot")

MAX_SUBSCRIBERS = 50
_SUBS_FILE = pathlib.Path(os.environ.get(
    "WAYANG_TG_SUBS_FILE", str(pathlib.Path(__file__).resolve().parents[1] / "data" / "tg_subscribers.json")))
_SUBS_LOCK = threading.Lock()
_SUBS: dict[str, set[int]] = {}  # dibagi antar-node: token -> kumpulan chat_id


def _subs_for(token: str) -> set[int]:
    with _SUBS_LOCK:
        if token not in _SUBS:
            ids: set[int] = set()
            try:
                ids = {int(x) for x in json.loads(_SUBS_FILE.read_text("utf-8")).get(token[-8:], [])}
            except Exception:
                pass
            _SUBS[token] = ids
        return _SUBS[token]


def _subs_for_unlocked(token: str) -> set[int]:
    """Versi tanpa kunci (pemanggil sudah memegang _SUBS_LOCK)."""
    if token not in _SUBS:
        ids: set[int] = set()
        try:
            ids = {int(x) for x in json.loads(_SUBS_FILE.read_text("utf-8")).get(token[-8:], [])}
        except Exception:
            pass
        _SUBS[token] = ids
    return _SUBS[token]


def _save_subs(token: str) -> None:
    try:
        _SUBS_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = json.loads(_SUBS_FILE.read_text("utf-8"))
        except Exception:
            data = {}
        data[token[-8:]] = sorted(_SUBS.get(token, set()))
        _SUBS_FILE.write_text(json.dumps(data), "utf-8")
    except Exception:
        log.warning("Gagal menyimpan daftar pelanggan Telegram", exc_info=True)


READONLY_CMDS = {"/start", "/stop", "/help", "/status"}

BUTTONS = [("Setujui blokir", "approve"), ("Abaikan", "ignore"), ("Buka konsol", "open")]


class ConsoleChannel:
    """Kanal internal: menyimpan pesan; dipakai konsol dan pengujian."""

    def __init__(self):
        self.messages: list[dict] = []

    def send(self, text: str, buttons: list[tuple[str, str]] | None = None) -> int:
        self.messages.append({"id": len(self.messages) + 1, "ts": time.time(),
                              "text": text, "buttons": buttons or []})
        return len(self.messages)


class TelegramChannel:
    """Kanal Telegram interaktif dengan dukungan tombol inline & perintah."""

    def __init__(self, token: str, chat_id: str | int, on_callback=None, on_command=None):
        self.token = str(token)
        self.chat_id = int(chat_id)
        self.on_callback = on_callback
        self.on_command = on_command
        self.messages: list[dict] = []
        self._offset = 0
        self._task: asyncio.Task | None = None

    def _send_sync(self, payload: dict) -> int:
        try:
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                json.dumps(payload).encode(), {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                res = json.loads(r.read())
                msg_id = res["result"]["message_id"]
                self.messages.append({"id": msg_id, "ts": time.time(),
                                      "text": payload.get("text", "")})
                return msg_id
        except Exception as e:
            log.warning("Gagal mengirim pesan Telegram: %s", e)
            return 0

    def send(self, text: str, buttons=None) -> int:
        """Alert ke chat pemilik (dengan tombol aksi) dan ke semua pelanggan /start (hanya-baca)."""
        with _SUBS_LOCK:
            others = sorted(_subs_for_unlocked(self.token) - {self.chat_id})
        for cid in [self.chat_id] + others:
            payload = {"chat_id": cid, "text": text}
            if buttons and cid == self.chat_id:  # hanya pemilik yang boleh menyetujui/mengabaikan
                payload["reply_markup"] = {"inline_keyboard": [[
                    {"text": label, "callback_data": f"{act}:{pid}"} for label, act, pid in buttons]]}
            # Kirim di background thread agar tidak memblokir event loop dan latensi Modbus/OT
            threading.Thread(target=self._send_retry, args=(payload,), daemon=True).start()
        return 1

    def _reply(self, chat_id: int, text: str) -> None:
        threading.Thread(target=self._send_retry, args=({"chat_id": chat_id, "text": text},),
                         daemon=True).start()

    def _handle_start(self, chat_id: int, name: str) -> None:
        subs = _subs_for(self.token)
        if chat_id != self.chat_id and chat_id not in subs and len(subs) >= MAX_SUBSCRIBERS:
            self._reply(chat_id, "Batas pelanggan notifikasi tercapai.")
            return
        with _SUBS_LOCK:
            subs.add(chat_id)
            _save_subs(self.token)
        self._reply(chat_id, (
            f"🛡️ WAYANG Dalang aktif, {name}.\n"
            "Chat ini sekarang menerima notifikasi serangan secara real-time "
            "(mode lihat-saja).\n"
            "Perintah: /status · /stop · /help"))

    def _send_retry(self, payload: dict, attempts: int = 4) -> int:
        """Kirim dengan percobaan ulang (backoff 2,4,8 dtk) agar alert tidak hilang saat jaringan goyah."""
        for i in range(attempts):
            mid = self._send_sync(payload)
            if mid:
                return mid
            if i < attempts - 1:
                time.sleep(min(2 ** (i + 1), 15))
        log.error("Alert Telegram GAGAL terkirim setelah %d percobaan", attempts)
        return 0

    async def poll_once(self) -> None:
        loop = asyncio.get_event_loop()
        url = f"https://api.telegram.org/bot{self.token}/getUpdates?offset={self._offset}&timeout=4"
        try:
            res_bytes = await loop.run_in_executor(None, lambda: urllib.request.urlopen(url, timeout=10).read())
            data = json.loads(res_bytes)
            for upd in data.get("result", []):
                self._offset = max(self._offset, upd["update_id"] + 1)
                if "callback_query" in upd:
                    cq = upd["callback_query"]
                    cb_id = cq["id"]
                    cb_data = cq.get("data", "")
                    cb_chat = (cq.get("message") or {}).get("chat", {}).get("id")
                    sender = cq.get("from", {}).get("username") or cq.get("from", {}).get("first_name") or "perwira"
                    # Konfirmasi callback ke Telegram UI
                    ack = urllib.request.Request(
                        f"https://api.telegram.org/bot{self.token}/answerCallbackQuery",
                        json.dumps({"callback_query_id": cb_id, "text": "Diproses Dalang..."}).encode(),
                        {"Content-Type": "application/json"})
                    await loop.run_in_executor(None, lambda: urllib.request.urlopen(ack, timeout=5))
                    if cb_chat != self.chat_id:
                        self._reply(cb_chat, "⛔ Hanya perwira jaga yang dapat menekan tombol ini.")
                    elif self.on_callback:
                        reply = self.on_callback(cb_data, who=f"@{sender}")
                        self.send(f"✅ {reply}")
                elif "message" in upd and "text" in upd["message"]:
                    txt = upd["message"]["text"].strip()
                    chat = upd["message"].get("chat", {})
                    cid = chat.get("id")
                    if not txt.startswith("/") or cid is None:
                        continue
                    cmd = txt.split()[0].split("@")[0].lower()
                    who = (upd["message"].get("from", {}).get("first_name") or "perwira")
                    if cmd == "/start":
                        self._handle_start(cid, who)
                    elif cmd == "/stop":
                        with _SUBS_LOCK:
                            _subs_for_unlocked(self.token).discard(cid)
                            _save_subs(self.token)
                        self._reply(cid, "Notifikasi dihentikan. Kirim /start untuk mengaktifkan lagi.")
                    elif cmd == "/help":
                        self._reply(cid, "/start aktifkan notifikasi · /stop hentikan · /status ringkasan")
                    elif cmd not in READONLY_CMDS and cid != self.chat_id:
                        self._reply(cid, "⛔ Perintah ini hanya untuk perwira jaga.")
                    elif self.on_command:
                        reply = self.on_command(cmd)
                        if reply:
                            self._reply(cid, reply)
        except Exception:
            pass

    async def _loop(self) -> None:
        while True:
            await self.poll_once()
            await asyncio.sleep(1)

    def start_polling(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self._loop())

    def stop_polling(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None


class MultiChannel:
    """Mengalirkan alert ke beberapa kanal sekaligus (Internal Console + Telegram)."""

    def __init__(self, channels: list):
        self.channels = channels

    @property
    def messages(self) -> list[dict]:
        for ch in self.channels:
            if hasattr(ch, "messages"):
                return ch.messages
        return []

    def send(self, text: str, buttons=None) -> int:
        ret = 0
        for ch in self.channels:
            try:
                r = ch.send(text, buttons)
                if r:
                    ret = r
            except Exception:
                pass
        return ret


class BotDalang:
    def __init__(self, channel, approvals, autonomy, console_url: str = "http://localhost:8080"):
        self.channel = channel
        self.approvals = approvals
        self.autonomy = autonomy
        self.console_url = console_url

    @staticmethod
    def _tech(summary: dict) -> str:
        return ", ".join(summary.get("techniques", [])[:4]) or "-"

    def info(self, text: str) -> None:
        self.channel.send("ℹ️ " + text)

    def notify_divert(self, summary: dict, proposal, reason: str) -> None:
        text = (f"⚠️ TIPUAN DISENTUH · {summary['satuan']}\n"
                f"Sumber: {summary['src']}\n"
                f"Tahap: {summary['stage']} (kedalaman {summary['depth']})\n"
                f"Teknik: {self._tech(summary)}\n"
                f"Alasan: {reason}\n"
                f"Aset asli: tidak tersentuh.\n"
                f"Tingkat otonomi: L{self.autonomy.level} {self.autonomy.name}")
        btns = [(label, act, proposal.id if proposal else summary["session"])
                for label, act in BUTTONS] if proposal else None
        if btns:
            self.channel.send(text, btns)
        else:
            self.channel.send(text)

    def notify_diverted_write(self, src: str, unit: int, fc: int, addr: int | None,
                              val: int | list[int] | None, reason: str = "") -> None:
        text = (f"🚨 PERINGATAN OPERASIONAL: PENULISAN DIALIHKAN KE BAYANGAN!\n"
                f"Sumber: {src} · Unit: {unit} · FC: {fc}\n"
                f"Alamat: {addr} · Nilai: {val}\n"
                f"Status: PERINTAH TULIS DIBUANG DARI PLC RIIL (Aset fisik aman).\n"
                f"Catatan: Bila ini tindakan teknisi sah, aktifkan 'Mode Perawatan' di konsol.")
        self.channel.send(text)

    def notify_campaign(self, campaign: dict) -> None:
        self.channel.send(
            f"🚨 KAMPANYE TERDETEKSI\nSatuan: {', '.join(campaign['satuan'])}\n"
            f"Bukti: {campaign['bukti']}\n{campaign['catatan']}")

    def handle_callback(self, data: str, who: str = "perwira_jaga") -> str:
        action, _, ident = data.partition(":")
        if action == "approve":
            p = self.approvals.approve(ident, who)
            return f"Blokir {p.src} disetujui oleh {who}."
        if action == "ignore":
            self.approvals.ignore(ident, who)
            return "Draf diabaikan oleh perwira jaga."
        if action == "open":
            return f"Buka konsol: {self.console_url}/#sesi={ident}"
        raise ValueError(f"aksi tidak dikenal: {action}")

    def handle_command(self, cmd: str) -> str | None:
        c = cmd.lower()
        if c.startswith("/status"):
            return (f"🛡️ [STATUS DALANG]\nTingkat Otonomi: L{self.autonomy.level} ({self.autonomy.name})\n"
                    f"Draf tertunda: {len(self.approvals.pending())}\n"
                    f"Aset Terlindungi: 100% (Semua efek tulis ke bayangan bersifat log-only)")
        if c.startswith("/kill"):
            self.autonomy.kill_switch("telegram_dalang")
            return "🛑 SAKLAR DARURAT DIAKTIFKAN: Otonomi diturunkan ke L0 (Hanya Amati)."
        return None
