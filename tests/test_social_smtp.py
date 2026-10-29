import asyncio
import smtplib
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from engine.social import SocialDecoys
from shadows.smtp_shadow import SMTPShadow


def test_smtp_shadow_captures_phishing_and_canaries():
    async def go():
        social = SocialDecoys("Kodim-DEMO-03", 1, b"secret123", domain="cyber.steamcraft.online")
        people = social.make_directory(3)
        doc = social.make_honeydoc("nota-001")
        decoy_email = people[0]["email"]

        smtp = SMTPShadow(social, domain="cyber.steamcraft.online")
        server = await smtp.serve("127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            # Kirim email phishing uji coba ke persona umpan
            def send_mail():
                with smtplib.SMTP("127.0.0.1", port) as client:
                    client.helo("attacker.net")
                    msg = (f"From: badguy@attacker.net\r\n"
                           f"To: {decoy_email}\r\n"
                           f"Subject: Pembaruan Akun Penting\r\n\r\n"
                           f"Mohon verifikasi kode berikut: {doc['frasa_kanari']}\r\n")
                    client.sendmail("badguy@attacker.net", [decoy_email], msg)

            await asyncio.to_thread(send_mail)

            # Verifikasi bahwa decoy email dan frasa kanari tertangkap
            hits = social.recon_map()
            assert any(h["kind"] == "decoy_email_received" and h["id"] == decoy_email for h in hits)
            assert any(h["kind"] == "canary_phrase_seen" and h["id"] == "nota-001" for h in hits)
            assert smtp.received_count == 1
        finally:
            server.close()

    asyncio.run(go())
