import email
import email.policy
import email.utils
import imaplib
import logging
import os
import socket
import ssl
import tempfile
import time
from email.message import Message
from typing import Iterable

import cups

DEFAULT_CHECK_INTERVAL = 60
DEFAULT_IMAP_PORT = 993

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _get_env(name: str, default: str | None = None) -> str | None:
    """Read and strip whitespace from an environment variable."""

    value = os.getenv(name, default)
    return value.strip() if isinstance(value, str) else value


def _get_int_env(name: str, default: int) -> int:
    """Read an integer environment variable with validation and fallback."""

    raw_value = _get_env(name)
    if raw_value in (None, ""):
        return default

    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer, got {raw_value!r}.") from exc


IMAP_SERVER = _get_env("IMAP_SERVER")
IMAP_PORT = _get_int_env("IMAP_PORT", DEFAULT_IMAP_PORT)
IMAP_USER = _get_env("IMAP_USER")
IMAP_PASSWORD = _get_env("IMAP_PASSWORD")
CHECK_INTERVAL = _get_int_env("CHECK_INTERVAL", DEFAULT_CHECK_INTERVAL)

CUPS_PRINTER_NAME = _get_env("CUPS_PRINTER_NAME")
PRINT_SIDES = _get_env("PRINT_SIDES", "two-sided-long-edge")
SENDER_WHITELIST = _get_env("ALLOWED_SENDERS")


def _parse_sender_whitelist(raw_addresses: str | None) -> set[str]:
    """Parse a comma- or whitespace-separated whitelist of email addresses."""

    if not raw_addresses:
        return set()

    return {
        addr.lower()
        for _, addr in email.utils.getaddresses([raw_addresses])
        if addr
    }


ALLOWED_SENDERS = _parse_sender_whitelist(SENDER_WHITELIST)

_LOGGED_SENDER_WHITELIST = False
_LOGGED_IMAP_CONFIG = False


def _log_sender_whitelist_once() -> None:
    """Emit a startup log describing whitelist settings exactly once."""

    global _LOGGED_SENDER_WHITELIST

    if _LOGGED_SENDER_WHITELIST:
        return

    _LOGGED_SENDER_WHITELIST = True

    if ALLOWED_SENDERS:
        logger.info(
            "Sender-Whitelist aktiv (%d Adresse(n)): %s",
            len(ALLOWED_SENDERS),
            ", ".join(sorted(ALLOWED_SENDERS)),
        )
    else:
        logger.info("Keine Sender-Whitelist gesetzt; alle Absender sind erlaubt.")


def _log_imap_config_once() -> None:
    """Emit a startup log with IMAP connection details (without password)."""

    global _LOGGED_IMAP_CONFIG

    if _LOGGED_IMAP_CONFIG:
        return

    _LOGGED_IMAP_CONFIG = True
    logger.info(
        "Starte IMAP-Verbindung zu %s:%s mit Benutzer '%s'",
        IMAP_SERVER,
        IMAP_PORT,
        IMAP_USER,
    )


def _secure_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    try:
        context.verify_flags |= ssl.VERIFY_X509_STRICT
    except AttributeError:  # pragma: no cover - depends on OpenSSL build
        pass
    return context


def _resolve_printer(connection: cups.Connection) -> str:
    """Determine which printer to use via explicit env or CUPS default."""

    if CUPS_PRINTER_NAME:
        return CUPS_PRINTER_NAME

    default = connection.getDefault()
    if default:
        return default

    raise ValueError(
        "No CUPS printer configured. Set CUPS_PRINTER_NAME or a system default printer."
    )


def send_cups_print_job(pdf_bytes: bytes, job_name: str) -> None:
    """Send PDF bytes to a printer managed by CUPS."""

    safe_name = job_name.replace("\r", " ").replace("\n", " ") or "email-job.pdf"

    try:
        connection = cups.Connection()
    except RuntimeError as exc:  # pragma: no cover - runtime
        logger.error("Failed to connect to CUPS server: %s", exc)
        raise RuntimeError(f"Failed to connect to CUPS server: {exc}") from exc

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(pdf_bytes)
        tmp.flush()
        tmp_path = tmp.name

    options = {}
    if PRINT_SIDES:
        options["sides"] = PRINT_SIDES

    try:
        printer = _resolve_printer(connection)
        logger.info("Submitting print job '%s' to printer '%s'", safe_name, printer)
        job_id = connection.printFile(printer, tmp_path, safe_name, options)
        logger.info(
            "CUPS accepted job %s for printer '%s' with title '%s'",
            job_id,
            printer,
            safe_name,
        )
    except cups.IPPError as exc:  # pragma: no cover - runtime
        logger.error("CUPS IPP error while printing: %s", exc)
        raise RuntimeError(f"CUPS IPP error while printing: {exc}") from exc
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            logger.warning("Temporary print file '%s' could not be deleted", tmp_path)

    logger.debug(
        "Submitted CUPS job %s to printer '%s' with title '%s'", job_id, printer, safe_name
    )


def extract_pdf_parts(msg: Message) -> Iterable[tuple[str, bytes]]:
    """Yield (filename, payload) for each PDF attachment."""

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue

        disposition = part.get("Content-Disposition")
        if not disposition:
            continue

        filename = part.get_filename()
        if filename and filename.lower().endswith(".pdf"):
            payload = part.get_payload(decode=True)
            if payload:
                yield filename, payload


def extract_sender_addresses(msg: Message) -> set[str]:
    """Return lower-cased sender email addresses from the message."""

    from_headers = msg.get_all("from", [])
    return {
        addr.lower()
        for _, addr in email.utils.getaddresses(from_headers)
        if addr
    }


def _is_sender_allowed(senders: set[str]) -> bool:
    """Return True if the message's senders match the optional whitelist."""

    if not ALLOWED_SENDERS:
        return True

    return bool(senders.intersection(ALLOWED_SENDERS))


def process_message(msg: Message, message_uid: bytes, mail: imaplib.IMAP4_SSL) -> None:
    """Process PDFs in the email and mark as seen after successful printing."""

    printed_any = False
    printed_count = 0
    for filename, payload in extract_pdf_parts(msg):
        send_cups_print_job(payload, filename)
        printed_any = True
        printed_count += 1

    if printed_any:
        mail.store(message_uid, "+FLAGS", "(\\Seen)")
        logger.info(
            "Druckauftrag ausgeführt: %d PDF(s) aus Nachricht UID %s verarbeitet",
            printed_count,
            message_uid,
        )
    else:
        logger.warning("No PDF attachments found in message UID %s", message_uid)


def _ensure_required_env() -> None:
    if not IMAP_SERVER:
        raise ValueError("IMAP_SERVER must be set.")
    if not IMAP_USER:
        raise ValueError("IMAP_USER must be set.")
    if not IMAP_PASSWORD:
        raise ValueError("IMAP_PASSWORD must be set.")


def _connect_imap() -> imaplib.IMAP4_SSL:
    try:
        return imaplib.IMAP4_SSL(
            IMAP_SERVER, IMAP_PORT, ssl_context=_secure_ssl_context(), timeout=15
        )
    except socket.gaierror as exc:  # pragma: no cover - DNS/runtime
        logger.error(
            "Unable to resolve IMAP server host '%s': %s", IMAP_SERVER, exc.strerror or exc
        )
        raise RuntimeError(
            f"Unable to resolve IMAP server host '{IMAP_SERVER}': {exc.strerror or exc}"
        ) from exc


def _fetch_unseen_messages(mail: imaplib.IMAP4_SSL) -> list[bytes]:
    status, _ = mail.select("INBOX")
    if status != "OK":
        logger.error("Failed to select INBOX; IMAP status: %s", status)
        raise RuntimeError("Failed to select INBOX for the configured account.")

    status, messages = mail.search(None, "(UNSEEN)")
    if status != "OK":
        logger.error("Failed to search for unseen messages; IMAP status: %s", status)
        return []
    if not messages:
        return []

    return [uid for uid in messages[0].split() if uid]


def check_mail() -> None:
    """Connect to IMAP and check for new unread emails."""

    _log_sender_whitelist_once()
    _ensure_required_env()
    _log_imap_config_once()

    mail = _connect_imap()
    with mail:
        status, _ = mail.login(IMAP_USER, IMAP_PASSWORD)
        if status != "OK":
            logger.error("IMAP login failed with status: %s", status)
            return
        for num in _fetch_unseen_messages(mail):
            status, msg_data = mail.fetch(num, "(RFC822)")
            if status != "OK" or not msg_data:
                logger.warning("Skipping message UID %s due to fetch status: %s", num, status)
                continue

            raw_message = msg_data[0][1]
            msg = email.message_from_bytes(raw_message, policy=email.policy.default)

            senders = extract_sender_addresses(msg)
            if not _is_sender_allowed(senders):
                logger.info(
                    "Skipping message UID %s from sender(s) %s not in whitelist",
                    num,
                    ", ".join(sorted(senders)) if senders else "<unknown>",
                )
                continue

            process_message(msg, num, mail)


if __name__ == "__main__":
    while True:
        try:
            check_mail()
        except Exception as e:  # pragma: no cover - runtime guardrail
            logger.exception("Error during mail check: %s", e)
        time.sleep(CHECK_INTERVAL)
