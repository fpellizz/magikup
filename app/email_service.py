"""
Outbound email service for MagikUp.

Stdlib-only SMTP client (``smtplib`` + ``ssl`` + ``email.*``) — no new
dependency. Reads the saved [smtp] config via ``config.get_smtp_config()`` and
exposes a small, reusable primitive:

    send_email(to, subject, html, text=None, *, reply_to=None) -> None
    send_test_email(recipient) -> None

Design notes / house rules:
- NEVER logs the SMTP password, the AUTH exchange, or message bodies. On error
  we log the exception *class* + SMTP status code + host/port only.
- Messages are built with ``email.message.EmailMessage`` (headers encoded
  safely); CR/LF in headers/recipients is rejected up front to prevent
  header injection.
- A bounded socket timeout (from ``timeout_seconds``) is applied to every SMTP
  operation so a hung server can never block indefinitely. ``smtplib`` is
  blocking — async call sites must run these functions in a threadpool
  (e.g. ``asyncio.to_thread`` / ``run_in_threadpool``).
- Failures are mapped to a small set of typed exceptions so the API layer can
  produce specific, user-safe messages (never a raw traceback).
"""

import re
import ssl
import socket
import smtplib
import logging
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, formatdate

from . import config

logger = logging.getLogger(__name__)

# Conservative RFC-5322-ish single-address check. Deliberately permissive on the
# local part but rejects whitespace, commas, and CR/LF (header-injection safe).
_EMAIL_RE = re.compile(r"^[^@\s,<>]+@[^@\s,<>]+\.[^@\s,<>]+$")


# =============================================================================
# Typed exceptions
# =============================================================================

class EmailError(Exception):
    """Base class for all email_service errors. Carries a user-safe ``message``
    and a stable ``code`` the API layer maps to an HTTP response."""
    code = "unknown"

    def __init__(self, message: str = ""):
        super().__init__(message or self.__class__.__name__)
        self.message = message or self.__class__.__name__


class EmailNotConfigured(EmailError):
    code = "not_configured"


class InvalidRecipient(EmailError):
    code = "invalid_recipient"


class EmailAuthError(EmailError):
    code = "auth"


class EmailConnectionError(EmailError):
    code = "connection"


class EmailTLSError(EmailError):
    code = "tls"


class EmailTimeout(EmailError):
    code = "timeout"


class EmailSendError(EmailError):
    code = "unknown"


# =============================================================================
# Validation helpers
# =============================================================================

def is_valid_email(addr: str) -> bool:
    """Conservative single-address validation (also rejects CR/LF)."""
    if not addr or not isinstance(addr, str):
        return False
    if len(addr) > 320:
        return False
    return bool(_EMAIL_RE.match(addr.strip()))


def _reject_header_injection(*values: str) -> None:
    """Raise EmailSendError if any header value contains CR/LF."""
    for v in values:
        if v and ("\r" in v or "\n" in v):
            raise EmailSendError("Invalid header value (line breaks not allowed).")


def _normalize_recipients(to) -> list:
    """Accept a single address or a list; validate each. Returns a clean list."""
    if isinstance(to, str):
        recipients = [to]
    else:
        recipients = list(to or [])
    cleaned = []
    for r in recipients:
        r = (r or "").strip()
        if not is_valid_email(r):
            raise InvalidRecipient(f"Invalid recipient address: {r or '(empty)'}")
        cleaned.append(r)
    if not cleaned:
        raise InvalidRecipient("No recipient address provided.")
    return cleaned


# =============================================================================
# Message building
# =============================================================================

def _html_to_text(html: str) -> str:
    """Minimal HTML->text fallback (strip tags, collapse whitespace)."""
    if not html:
        return ""
    text = re.sub(r"(?is)<br\s*/?>", "\n", html)
    text = re.sub(r"(?is)</p>", "\n\n", text)
    text = re.sub(r"(?is)<[^>]+>", "", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _build_message(smtp: config.SMTPConfig, recipients: list, subject: str,
                   html: str, text: str = None, reply_to: str = None) -> EmailMessage:
    # Guard the ACTUAL reply-to that will be written to the header — including the
    # value coming from the saved config (smtp.reply_to), not just the call arg.
    effective_reply_to = reply_to or smtp.reply_to
    _reject_header_injection(subject, smtp.from_address, smtp.from_name, effective_reply_to or "")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((smtp.from_name or "", smtp.from_address))
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    try:
        domain = smtp.from_address.split("@", 1)[1] if "@" in smtp.from_address else None
        msg["Message-ID"] = make_msgid(domain=domain)
    except Exception:
        msg["Message-ID"] = make_msgid()

    if effective_reply_to:
        msg["Reply-To"] = effective_reply_to

    plain = text if text is not None else _html_to_text(html)
    msg.set_content(plain or "")
    if html:
        msg.add_alternative(html, subtype="html")
    return msg


# =============================================================================
# Public API
# =============================================================================

def send_email(to, subject: str, html: str, text: str = None, *, reply_to: str = None) -> None:
    """Send an email using the saved [smtp] config.

    ``to`` may be a single address string or a list of addresses. Raises a typed
    ``EmailError`` subclass on any failure; returns None on success.
    """
    smtp = config.get_smtp_config()

    if not smtp.enabled or not smtp.host:
        raise EmailNotConfigured("Email is not configured or is disabled.")

    recipients = _normalize_recipients(to)

    timeout = smtp.timeout_seconds or config.DEFAULT_SMTP_TIMEOUT
    if timeout < config.SMTP_TIMEOUT_MIN:
        timeout = config.SMTP_TIMEOUT_MIN
    elif timeout > config.SMTP_TIMEOUT_MAX:
        timeout = config.SMTP_TIMEOUT_MAX

    security = (smtp.security or config.DEFAULT_SMTP_SECURITY).lower()

    msg = _build_message(smtp, recipients, subject, html, text=text, reply_to=reply_to)

    server = None
    try:
        context = ssl.create_default_context()
        if security == "ssl":
            server = smtplib.SMTP_SSL(smtp.host, smtp.port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(smtp.host, smtp.port, timeout=timeout)
            if security == "starttls":
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
            # security == "none": plaintext, no TLS (discouraged; UI warns)

        if smtp.username:
            server.login(smtp.username, smtp.password)

        server.send_message(msg)

    except smtplib.SMTPAuthenticationError as e:
        logger.error("SMTP auth failed to %s:%s (code %s)", smtp.host, smtp.port,
                     getattr(e, "smtp_code", "?"))
        raise EmailAuthError("Authentication failed. Check username/password.")
    except (smtplib.SMTPHeloError,) as e:
        logger.error("SMTP HELO/EHLO error to %s:%s: %s", smtp.host, smtp.port, e.__class__.__name__)
        raise EmailConnectionError(f"Could not negotiate with {smtp.host}:{smtp.port}.")
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as e:
        logger.error("SMTP recipient/sender refused by %s:%s: %s", smtp.host, smtp.port, e.__class__.__name__)
        raise EmailSendError("The server refused the sender or recipient address.")
    except ssl.SSLError as e:
        logger.error("SMTP TLS error to %s:%s: %s", smtp.host, smtp.port, e.__class__.__name__)
        raise EmailTLSError("TLS negotiation failed. Try SSL/TLS mode or check the server certificate.")
    except smtplib.SMTPNotSupportedError as e:
        logger.error("SMTP feature not supported by %s:%s: %s", smtp.host, smtp.port, e.__class__.__name__)
        raise EmailTLSError("TLS/STARTTLS not supported by the server. Try a different security mode.")
    except (socket.timeout, TimeoutError):
        logger.error("SMTP timeout to %s:%s after %ss", smtp.host, smtp.port, timeout)
        raise EmailTimeout(f"Timed out after {timeout}s.")
    except (ConnectionRefusedError, socket.gaierror, OSError) as e:
        logger.error("SMTP connection error to %s:%s: %s", smtp.host, smtp.port, e.__class__.__name__)
        raise EmailConnectionError(
            f"Could not connect to {smtp.host}:{smtp.port}. Check host/port and egress.")
    except smtplib.SMTPException as e:
        logger.error("SMTP error to %s:%s: %s", smtp.host, smtp.port, e.__class__.__name__)
        raise EmailSendError("Failed to send email. Check the SMTP server settings.")
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass


def send_test_email(recipient: str) -> None:
    """Send a small fixed test message using the saved SMTP config.

    Raises a typed ``EmailError`` subclass on failure; returns None on success.
    """
    # Validate the recipient before touching the network.
    if not is_valid_email((recipient or "").strip()):
        raise InvalidRecipient(f"Invalid recipient address: {recipient or '(empty)'}")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    subject = "MagikUp test email"
    text = (
        "This is a test email from MagikUp.\n\n"
        f"Sent at: {now}\n\n"
        "If you received this, your SMTP settings are working."
    )
    html = (
        "<html><body>"
        "<p>This is a test email from <strong>MagikUp</strong>.</p>"
        f"<p>Sent at: {now}</p>"
        "<p>If you received this, your SMTP settings are working.</p>"
        "</body></html>"
    )
    send_email(recipient.strip(), subject, html, text=text)
