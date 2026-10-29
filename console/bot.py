"""Bot Dalang (Bab 11): ringkasan satu layar untuk perwira jaga, bahasa Indonesia.

Tombol: "Setujui blokir", "Abaikan", "Buka konsol". Kanal dapat diganti
(kanal internal, Telegram). Kanal bawaan tidak butuh jaringan.
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import urllib.request

log = logging.getLogger("wayang.bot")

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
        payload = {"chat_id": self.chat_id, "text": text}
        if buttons:
            payload["reply_markup"] = {"inline_keyboard": [[
                {"text": label, "callback_data": f"{act}:{pid}"} for label, act, pid in buttons]]}
        # Kirim di background thread agar tidak memblokir event loop dan latensi Modbus/OT
        threading.Thread(target=self._send_sync, args=(payload,), daemon=True).start()
        return 1

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
                    sender = cq.get("from", {}).get("username") or cq.get("from", {}).get("first_name") or "perwira"
                    # Konfirmasi callback ke Telegram UI
                    ack = urllib.request.Request(
                        f"https://api.telegram.org/bot{self.token}/answerCallbackQuery",
                        json.dumps({"callback_query_id": cb_id, "text": "Diproses Dalang..."}).encode(),
                        {"Content-Type": "application/json"})
                    await loop.run_in_executor(None, lambda: urllib.request.urlopen(ack, timeout=5))
                    if self.on_callback:
                        reply = self.on_callback(cb_data, who=f"@{sender}")
                        self.send(f"✅ {reply}")
                elif "message" in upd and "text" in upd["message"]:
                    txt = upd["message"]["text"].strip()
                    if txt.startswith("/") and self.on_command:
                        reply = self.on_command(txt)
                        if reply:
                            self.send(reply)
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
