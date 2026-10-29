"""Bayangan SMTP (Bab 10: Bayangan Sosial).

Meniru mail gateway penerima untuk subdomain decoy (mis. cyber.steamcraft.online).
Menangkap percobaan email phishing ke persona fiktif dan mendeteksi frasa kanari.
"""
from __future__ import annotations

import asyncio
import email
import email.policy
import logging

log = logging.getLogger("wayang.smtp")


class SMTPShadow:
    def __init__(self, social, domain: str = "cyber.steamcraft.online",
                 banner: str = "ESMTP Postfix (Ubuntu)"):
        self.social = social
        self.domain = domain
        self.banner = banner
        self.received_count = 0

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        src = writer.get_extra_info("peername")[0]
        writer.write(f"220 {self.domain} {self.banner}\r\n".encode())
        await writer.drain()

        sender = "unknown"
        recipients = []
        data_mode = False
        body_lines = []

        try:
            while True:
                line_bytes = await reader.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")

                if data_mode:
                    if line == ".":
                        data_mode = False
                        full_body = "\r\n".join(body_lines)
                        self._process_message(src, sender, recipients, full_body)
                        writer.write(b"250 2.0.0 Ok: queued\r\n")
                        await writer.drain()
                        body_lines = []
                    else:
                        body_lines.append(line)
                    continue

                upper = line.upper()
                if upper.startswith("HELO") or upper.startswith("EHLO"):
                    writer.write(f"250-{self.domain}\r\n250 8BITMIME\r\n".encode())
                elif upper.startswith("MAIL FROM:"):
                    sender = line[10:].strip("<> ")
                    writer.write(b"250 2.1.0 Ok\r\n")
                elif upper.startswith("RCPT TO:"):
                    rcpt = line[8:].strip("<> ")
                    recipients.append(rcpt)
                    writer.write(b"250 2.1.5 Ok\r\n")
                elif upper.startswith("DATA"):
                    data_mode = True
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                elif upper.startswith("RSET"):
                    sender, recipients, body_lines = "unknown", [], []
                    writer.write(b"250 2.0.0 Ok\r\n")
                elif upper.startswith("NOOP"):
                    writer.write(b"250 2.0.0 Ok\r\n")
                elif upper.startswith("QUIT"):
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"500 5.5.2 Error: command not recognized\r\n")
                await writer.drain()
        except Exception as e:
            log.warning("SMTP client error: %s", e)
        finally:
            writer.close()

    def _process_message(self, src: str, sender: str, recipients: list[str], raw_text: str):
        self.received_count += 1
        msg = email.message_from_string(raw_text, policy=email.policy.default)
        subject = str(msg.get("Subject", ""))
        payload = msg.get_payload()
        body_text = payload if isinstance(payload, str) else raw_text

        # 1. Cek apakah penerima adalah persona umpan
        for rcpt in recipients:
            self.social.on_mail(rcpt, sender=f"{sender} ({src})", subject=subject)

        # 2. Cek apakah ada frasa kanari dokumen di dalam isi pesan
        self.social.scan_text(body_text, src=src, where=f"email to {', '.join(recipients)}")

    async def serve(self, host: str, port: int):
        return await asyncio.start_server(self._handle_client, host, port)
