"""SatuanNode: merakit semua komponen satu satuan (Bab 6.1).

Aset asli (real_addr) -> Kelir -> {aset asli | bayangan}; semua kejadian lewat
Gamelan ke Pipeline, lalu ke Dalang Console, Bot, dan Edge Sync.
"""
from __future__ import annotations

import asyncio
import os
import pathlib
import time

import uvicorn

from console.bot import BotDalang, ConsoleChannel, MultiChannel, TelegramChannel
from console.edge_sync import EdgeSync
from engine.approval import ApprovalQueue
from engine.attck_map import AttckMapper
from engine.autonomy import Autonomy, Blocklist
from engine.gamelan import Gamelan
from engine.pipeline import Pipeline
from engine.social import SocialDecoys
from engine.watchdog import WatchdogFailToWire
from evidence.hashchain import HashChain
from evidence.session_store import SessionStore
from kelir.mirror import StateMirror
from kelir.proxy import Kelir
from kelir.scoring import SessionScorer
from kelir.session import SessionRegistry
from shadows.hmi_web import make_hmi_app
from shadows.modbus_shadow import ShadowDevice
from shadows.smtp_shadow import SMTPShadow


class SatuanNode:
    def __init__(self, satuan: str, seed: int, real_addr: tuple[str, int],
                 out_dir: str, whitelist: set[str] | None = None,
                 time_scale: float = 1.0, level: int = 2, transport=None,
                 mirror_interval: float = 1.0, host: str = "127.0.0.1",
                 ports: tuple[int, int, int] = (0, 0, 0), start_hour: float | None = None,
                 db_path: str = ":memory:", lab_mode: bool = False):
        self.satuan = satuan
        self.host = host
        self.req_ports = ports
        self.ports: dict[str, int] = {}
        self.out = pathlib.Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.secret = f"rahasia-{satuan}-{seed}".encode()
        self.whitelist = set(whitelist or set())
        self.bus = Gamelan()
        self.sessions = SessionRegistry(prefix=f"{satuan.split('-')[-1]}")
        self.autonomy = Autonomy(level)
        self.blocklist = Blocklist()
        self.chain = HashChain()
        self.store = SessionStore(db_path)
        self.console_channel = ConsoleChannel()
        channels = [self.console_channel]
        tg_token = os.environ.get("TELEGRAM_BOT_TOKEN")
        tg_chat = os.environ.get("TELEGRAM_CHAT_ID")
        self.tg_channel = None
        self.approvals = ApprovalQueue(self.out, self.blocklist, self.whitelist,
                                      lab_mode=lab_mode)
        console_url = os.environ.get("CONSOLE_URL", "http://localhost:8080")
        self.bot = BotDalang(None, self.approvals, self.autonomy, console_url=console_url)
        if tg_token and tg_chat:
            self.tg_channel = TelegramChannel(
                tg_token, tg_chat,
                on_callback=lambda data, who: self.bot.handle_callback(data, who),
                on_command=lambda cmd: self.bot.handle_command(cmd)
            )
            channels.append(self.tg_channel)
        self.channel = MultiChannel(channels)
        self.bot.channel = self.channel
        self.edge = EdgeSync(transport, str(self.out / "outbox.db")
                             if db_path != ":memory:" else ":memory:") if transport else None
        self.pipeline = Pipeline(satuan, self.sessions, self.store, self.chain,
                                 AttckMapper(), self.autonomy, self.approvals,
                                 self.bot, self.edge)
        self.bus.subscribe(self.pipeline.on_event)
        self.shadow = ShadowDevice("depo_bbm_01", satuan, seed, self.sessions, self.bus,
                                   time_scale=time_scale, start_hour=start_hour)
        self.mirror = StateMirror(real_addr, mirror_interval)
        self.watchdog = WatchdogFailToWire(satuan, bus=self.bus)
        self.kelir = Kelir(satuan, real_addr, self.shadow, self.sessions,
                           SessionScorer(self.whitelist), self.bus, self.autonomy,
                           self.blocklist, self.mirror)
        self.social = SocialDecoys(satuan, seed, self.secret, self.bus,
                                   domain=os.environ.get("DECOY_DOMAIN"))
        self.personas = self.social.make_directory(5)
        self.smtp_shadow = SMTPShadow(self.social, domain=self.social.domain)
        self.hmi_app = make_hmi_app(self.shadow, self.secret)
        self._servers: list = []
        self._uv: uvicorn.Server | None = None
        self._uv_task = None

    async def start(self, with_hmi: bool = True) -> None:
        try:
            await self.mirror.poll_once()
        except (OSError, asyncio.TimeoutError):
            pass
        self.mirror.start()
        kp, sp, hp = self.req_ports
        ks = await self.kelir.serve(self.host, kp)
        ss = await self.shadow.serve(self.host, sp)
        self._servers = [ks, ss]
        self.ports["kelir"] = ks.sockets[0].getsockname()[1]
        self.ports["shadow"] = ss.sockets[0].getsockname()[1]

        smtp_p = int(os.environ.get("SMTP_PORT", "0"))
        if smtp_p > 0:
            smtp_s = await self.smtp_shadow.serve(self.host, smtp_p)
            self._servers.append(smtp_s)
            self.ports["smtp"] = smtp_s.sockets[0].getsockname()[1]
        if with_hmi:
            cfg = uvicorn.Config(self.hmi_app, host=self.host, port=hp, log_level="error")
            self._uv = uvicorn.Server(cfg)
            self._uv_task = asyncio.ensure_future(self._uv.serve())
            for _ in range(100):
                if self._uv.started:
                    break
                await asyncio.sleep(0.05)
            self.ports["hmi"] = (self._uv.servers[0].sockets[0].getsockname()[1]
                                 if self._uv.servers else hp)
        if self.tg_channel and not getattr(SatuanNode, "_tg_polling_active", False):
            SatuanNode._tg_polling_active = True
            self._is_tg_poller = True
            self.tg_channel.start_polling()

    async def stop(self) -> None:
        if getattr(self, "_is_tg_poller", False) and self.tg_channel:
            SatuanNode._tg_polling_active = False
            self.tg_channel.stop_polling()
        self.mirror.stop()
        for s in self._servers:
            s.close()
        if self._uv:
            self._uv.should_exit = True
            if self._uv_task:
                await asyncio.wait([self._uv_task], timeout=3)

    def sync(self) -> int:
        return self.edge.flush() if self.edge else 0

    def local_status(self) -> str:
        if any(s.diverted for s in self.sessions.by_id.values()) or self.sessions.by_id:
            return "Tipuan Disentuh"
        return "Aman"

