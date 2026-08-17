"""Pluggable email delivery for the control-plane (password reset + email verification).

Three implementations, one tiny interface, no third-party dependencies:

- ``SmtpMailer`` — real delivery over SMTP, configured entirely from environment variables
  (``DASTCORE_SMTP_HOST`` etc.). This is what a production deploy uses.
- ``LoggingMailer`` — the default when no SMTP host is set: it logs the message (including the
  link) under the ``dastcore.mail`` logger instead of sending it. Perfect for local/dev, and it
  keeps everything offline (the test suite never touches the network).
- ``MemoryMailer`` — collects messages in ``outbox`` so tests can assert on what was "sent".

``mailer_from_env`` picks SMTP when configured, else the logging fallback.
"""

from __future__ import annotations

import logging
import os
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Protocol

logger = logging.getLogger("dastcore.mail")


class Mailer(Protocol):
    """Anything that can deliver a plain-text email."""

    def send(self, to: str, subject: str, body: str) -> None: ...


@dataclass
class LoggingMailer:
    """Default mailer: log the message instead of sending it (dev / no SMTP configured)."""

    sender: str = "dastcore <no-reply@dastcore.local>"

    def send(self, to: str, subject: str, body: str) -> None:
        logger.info("email (not sent — no SMTP configured)\n  to: %s\n  subject: %s\n  %s", to, subject, body)


@dataclass
class MemoryMailer:
    """Test mailer: keep every message in ``outbox`` for assertions."""

    sender: str = "dastcore <no-reply@dastcore.local>"
    outbox: list[tuple[str, str, str]] = field(default_factory=list)

    def send(self, to: str, subject: str, body: str) -> None:
        self.outbox.append((to, subject, body))


@dataclass
class SmtpMailer:
    """Deliver over SMTP. STARTTLS by default; set ``use_tls=False`` only for a trusted relay."""

    host: str
    port: int = 587
    username: str = ""
    password: str = ""
    sender: str = "dastcore <no-reply@dastcore.local>"
    use_tls: bool = True

    def send(self, to: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)
        with smtplib.SMTP(self.host, self.port, timeout=15) as smtp:
            if self.use_tls:
                smtp.starttls()
            if self.username:
                smtp.login(self.username, self.password)
            smtp.send_message(message)


def mailer_from_env() -> Mailer:
    """SMTP mailer when ``DASTCORE_SMTP_HOST`` is set, otherwise the logging fallback."""
    host = os.environ.get("DASTCORE_SMTP_HOST", "").strip()
    sender = os.environ.get("DASTCORE_MAIL_FROM", "dastcore <no-reply@dastcore.local>").strip()
    if not host:
        return LoggingMailer(sender=sender)
    return SmtpMailer(
        host=host,
        port=int(os.environ.get("DASTCORE_SMTP_PORT", "587")),
        username=os.environ.get("DASTCORE_SMTP_USER", ""),
        password=os.environ.get("DASTCORE_SMTP_PASSWORD", ""),
        sender=sender,
        use_tls=os.environ.get("DASTCORE_SMTP_TLS", "1") not in ("0", "false", "no"),
    )
