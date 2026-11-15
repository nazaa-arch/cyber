"""GERBANG BYPASS — pintu depan Modbus/TCP dengan mode bypass aman (fail-to-wire).

Gerbang berjalan di thread dan event loop SENDIRI, terpisah dari Kelir. Jika Kelir
membeku (event loop macet karena badai serangan, OOM, bug) atau server-nya mati,
Gerbang tetap hidup dan mengambil alih:

    NORMAL  : semua koneksi diteruskan apa adanya ke Kelir; IP klien asli dibawa
              lewat header PROXY v1 sehingga penilaian sesi Kelir tetap akurat.
    BYPASS  : Kelir dianggap gagal. Hanya IP operator di daftar putih yang boleh
              tersambung LANGSUNG ke PLC, dan hanya untuk perintah BACA
              (FC 1/2/3/4/43). Perintah tulis dijawab exception Modbus 0x01 dan
              dicatat. Semua sumber lain diputus — tidak ada jalur ke PLC dan tidak
              ada bayangan (bayangan ikut hidup di proses Kelir).

Peralihan dikendalikan WatchdogFailToWire (3 detak gagal berturut-turut). Bila Kelir
jatuh-bangun berulang, bypass dikunci aktif sampai operator konfirmasi manual.

Batasan: Gerbang hidup di proses yang sama dengan node. Bila seluruh proses atau
mesin mati, Gerbang ikut mati — untuk itu tetap dibutuhkan bypass perangkat keras
(bypass NIC / ACL switch yang hanya meloloskan IP operator).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import threading
import time
from typing import Callable

from engine.watchdog import WatchdogFailToWire
from shadows import modbus_proto as mp

log = logging.getLogger("wayang.gerbang")

PLC_CONNECT_TIMEOUT_S = 2.0
PLC_REPLY_TIMEOUT_S = 3.0
DROP_EVENT_DEDUP_S = 60.0


class _ThreadSafeBus:
    """Teruskan event watchdog dari thread Gerbang ke callback node."""

    def __init__(self, notify: Callable[[dict], None] | None):
        self.notify = notify

    def publish(self, ev: dict) -> None:
        if self.notify:
            try:
                self.notify(ev)
            except Exception:
                log.exception("Gagal meneruskan event Gerbang")


class GerbangBypass:
    def __init__(self, satuan: str, listen: tuple[str, int], kelir_addr: tuple[str, int],
                 plc_addr: tuple[str, int], whitelist: set[str],
                 health_probe: Callable[[], bool], blocklist=None,
                 notify: Callable[[dict], None] | None = None,
                 alert: Callable[[str], None] | None = None,
                 interval_s: float = 0.1, miss_threshold: int = 3,
                 flap_limit: int = 3, flap_window_s: float = 600.0):
        self.satuan = satuan
        self.listen = listen
        self.kelir_addr = kelir_addr
        self.plc_addr = plc_addr
        self.whitelist = whitelist            # referensi hidup: perubahan daftar putih ikut berlaku
        self.blocklist = blocklist
        self.health_probe = health_probe
        self.notify = notify
        self.alert = alert
        self.port: int | None = None
        self.bypass = False
        self.stats = {"normal_conns": 0, "bypass_conns": 0, "bypass_reads": 0,
                      "bypass_writes_blocked": 0, "bypass_dropped": 0}
        self.watchdog = WatchdogFailToWire(
            satuan, bus=_ThreadSafeBus(notify), heartbeat_interval_s=interval_s,
            miss_threshold=miss_threshold, relay_actuator=self._switch,
            flap_limit=flap_limit, flap_window_s=flap_window_s)
        self._conns: set[tuple[str, asyncio.StreamWriter]] = set()
        self._last_drop_event: dict[str, float] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._server = None
        self._ready = threading.Event()
        self._error: BaseException | None = None

    # ------------------------------------------------------------------ siklus
    def start(self) -> int:
        self._thread = threading.Thread(target=self._run, name=f"gerbang-{self.satuan}",
                                        daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("Gerbang Bypass gagal mulai (timeout)")
        if self._error:
            raise RuntimeError(f"Gerbang Bypass gagal mulai: {self._error}")
        return self.port

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._server = self._loop.run_until_complete(
                asyncio.start_server(self._handle, *self.listen))
            self.port = self._server.sockets[0].getsockname()[1]
            self._loop.create_task(self.watchdog.monitor_loop(self._probe))
        except BaseException as e:  # noqa: BLE001 - dilaporkan ke start()
            self._error = e
            self._ready.set()
            return
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    def stop(self) -> None:
        loop = self._loop
        if not loop or loop.is_closed():
            return

        async def _shutdown():
            self.watchdog.running = False
            if self._server:
                self._server.close()
            for _, w in list(self._conns):
                w.close()
            for t in [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]:
                t.cancel()
            loop.stop()

        asyncio.run_coroutine_threadsafe(_shutdown(), loop)
        if self._thread:
            self._thread.join(5)

    # --------------------------------------------------------------- kendali
    def _probe(self) -> bool:
        try:
            return bool(self.health_probe())
        except Exception:
            return False

    def _switch(self, bypass: bool) -> None:
        """Dipanggil watchdog (di thread Gerbang) saat jalur harus dipindah."""
        self.bypass = bypass
        # Putus koneksi jalur lama agar klien menyambung ulang lewat jalur baru;
        # koneksi ke Kelir yang membeku tak akan pernah selesai dengan sendirinya.
        old = "normal" if bypass else "bypass"
        for mode, w in list(self._conns):
            if mode == old:
                w.close()
        if bypass:
            msg = (f"⚠️ MODE BYPASS AMAN AKTIF — {self.satuan}: proxy Kelir tidak merespons. "
                   f"Operator terdaftar tersambung langsung ke PLC (BACA-SAJA); "
                   f"sumber lain diputus. Periksa node WAYANG.")
        else:
            msg = f"✅ {self.satuan}: proxy Kelir pulih, jalur kembali normal lewat Kelir."
        log.warning(msg)
        if self.alert:
            # Telegram memakai HTTP sinkron: kirim di thread terpisah agar Gerbang tak tertahan.
            threading.Thread(target=self._safe_alert, args=(msg,), daemon=True).start()

    def _safe_alert(self, msg: str) -> None:
        try:
            self.alert(msg)
        except Exception:
            log.exception("Gagal mengirim peringatan bypass")

    def confirm_restore(self, who: str = "operator") -> tuple[bool, str]:
        """Aman dipanggil dari thread lain (API konsol)."""
        loop = self._loop
        if not loop or loop.is_closed():
            return False, "Gerbang tidak berjalan"

        async def _do():
            return self.watchdog.confirm_restore(who)

        return asyncio.run_coroutine_threadsafe(_do(), loop).result(5)

    def status(self) -> dict:
        return {"satuan": self.satuan, "mode": "BYPASS" if self.bypass else "NORMAL",
                "listen_port": self.port, "operators": sorted(self.whitelist),
                **self.watchdog.status(), "stats": dict(self.stats)}

    def _event(self, action: str, src: str | None, **extra) -> None:
        if self.notify:
            try:
                self.notify({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             "t_mono": time.monotonic(), "satuan": self.satuan,
                             "shadow": None, "proto": "modbus_tcp", "src": src,
                             "session": None, "action": action, "via": "gerbang", **extra})
            except Exception:
                log.exception("Gagal meneruskan event Gerbang")

    # -------------------------------------------------------------- koneksi
    async def _handle(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        mode = "bypass" if self.bypass else "normal"
        entry = (mode, writer)
        self._conns.add(entry)
        try:
            if mode == "bypass":
                await self._serve_bypass(peer[0], reader, writer)
            else:
                await self._serve_normal(peer, writer.get_extra_info("sockname"), reader, writer)
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            self._conns.discard(entry)
            writer.close()

    async def _serve_normal(self, peer, sock, reader, writer) -> None:
        self.stats["normal_conns"] += 1
        try:
            kr, kw = await asyncio.wait_for(asyncio.open_connection(*self.kelir_addr), 2.0)
        except (OSError, asyncio.TimeoutError):
            return                                   # watchdog akan memicu bypass
        fam = "TCP6" if ":" in peer[0] else "TCP4"
        dst = sock[0] if sock else ("::1" if fam == "TCP6" else "127.0.0.1")
        try:
            dst = str(ipaddress.ip_address(dst))
        except ValueError:
            dst = "::1" if fam == "TCP6" else "127.0.0.1"
        dport = sock[1] if sock else 0
        kw.write(f"PROXY {fam} {peer[0]} {dst} {peer[1]} {dport}\r\n".encode())
        entry = ("normal", kw)
        self._conns.add(entry)

        async def pipe(r, w):
            try:
                while True:
                    data = await r.read(65536)
                    if not data:
                        break
                    w.write(data)
                    await w.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                w.close()

        try:
            await asyncio.gather(pipe(reader, kw), pipe(kr, writer))
        finally:
            self._conns.discard(entry)
            kw.close()

    async def _serve_bypass(self, src: str, reader, writer) -> None:
        blocked = self.blocklist.is_blocked(src) if self.blocklist else False
        if src not in self.whitelist or blocked:
            self.stats["bypass_dropped"] += 1
            now = time.monotonic()
            if now - self._last_drop_event.get(src, -1e9) > DROP_EVENT_DEDUP_S:
                self._last_drop_event[src] = now
                self._event("bypass_drop", src,
                            reason="Mode bypass: hanya operator terdaftar yang dilayani")
            return
        self.stats["bypass_conns"] += 1
        try:
            pr, pw = await asyncio.wait_for(asyncio.open_connection(*self.plc_addr),
                                            PLC_CONNECT_TIMEOUT_S)
        except (OSError, asyncio.TimeoutError):
            return
        entry = ("bypass", pw)
        self._conns.add(entry)
        try:
            while True:
                fr = await mp.read_frame(reader)
                if fr is None:
                    return
                tid, unit, pdu = fr
                try:
                    req = mp.parse_pdu(pdu)
                except mp.ProtoError:
                    return                                       # frame cacat: putus
                if req.fc not in mp.READ_FUNCS:
                    self.stats["bypass_writes_blocked"] += 1
                    self._event("bypass_write_blocked", src, unit=unit, fc=req.fc,
                                addr=req.addr,
                                reason="Mode bypass baca-saja: perintah tulis tidak diteruskan ke PLC")
                    writer.write(mp.build_mbap(
                        tid, unit, mp.exception_pdu(req.fc, mp.ILLEGAL_FUNCTION)))
                    await writer.drain()
                    continue
                pw.write(mp.build_mbap(tid, unit, pdu))
                await pw.drain()
                resp = await asyncio.wait_for(mp.read_frame(pr), PLC_REPLY_TIMEOUT_S)
                if resp is None:
                    return
                self.stats["bypass_reads"] += 1
                writer.write(mp.build_mbap(tid, unit, resp[2]))
                await writer.drain()
        except asyncio.TimeoutError:
            return
        finally:
            self._conns.discard(entry)
            pw.close()
