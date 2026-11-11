"""Zero-send asynchronous raw TCP SMTP handshake & catch-all detection."""

from __future__ import annotations

import asyncio
import secrets
import struct
from dataclasses import dataclass
from typing import Callable, Coroutine, Optional, Tuple
from urllib.parse import urlparse


@dataclass(frozen=True)
class SMTPVerificationResult:
    """Outcome of a zero-send SMTP RCPT TO verification exchange."""

    deliverable: Optional[bool]
    is_catch_all: bool = False
    smtp_code: Optional[int] = None
    banner: str = ""
    reason: str = ""
    greylisted: bool = False


TransportConnector = Callable[
    [str, int, Optional[str], float],
    Coroutine[None, None, Tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]


async def default_tcp_or_socks_connect(
    host: str,
    port: int,
    proxy_url: Optional[str],
    timeout: float,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect directly or tunnel via a SOCKS5 / HTTP CONNECT proxy."""
    if not proxy_url:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)

    parsed = urlparse(proxy_url)
    proxy_host = parsed.hostname
    proxy_port = parsed.port
    if not proxy_host or not proxy_port:
        raise ValueError(f"Invalid proxy URL: {proxy_url}")

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port),
        timeout=timeout,
    )

    scheme = parsed.scheme.lower()
    if scheme.startswith("socks5"):
        await _socks5_handshake(
            reader,
            writer,
            target_host=host,
            target_port=port,
            username=parsed.username,
            password=parsed.password,
            timeout=timeout,
        )
        return reader, writer

    if scheme in {"http", "https"}:
        connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("ascii")
        writer.write(connect_req)
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if b"200" not in status_line:
            writer.close()
            raise ConnectionError(f"HTTP proxy CONNECT failed: {status_line.decode(errors='ignore').strip()}")
        # Consume remaining proxy response headers
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not line or line in {b"\r\n", b"\n"}:
                break
        return reader, writer

    writer.close()
    raise ValueError(f"Unsupported proxy scheme: {scheme}")


async def _socks5_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    username: Optional[str],
    password: Optional[str],
    timeout: float,
) -> None:
    """Minimal RFC 1928 SOCKS5 client handshake supporting no-auth and user/pass."""
    methods = b"\x00\x02" if (username and password) else b"\x00"
    writer.write(b"\x05" + bytes([len(methods)]) + methods)
    await writer.drain()
    resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
    if resp[0] != 0x05 or resp[1] == 0xFF:
        raise ConnectionError("SOCKS5 greeting rejected")

    if resp[1] == 0x02:
        u_bytes = (username or "").encode("utf-8")
        p_bytes = (password or "").encode("utf-8")
        writer.write(b"\x01" + bytes([len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes)
        await writer.drain()
        auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if auth_resp[1] != 0x00:
            raise ConnectionError("SOCKS5 authentication failed")

    host_bytes = target_host.encode("ascii")
    req = (
        b"\x05\x01\x00\x03"
        + bytes([len(host_bytes)])
        + host_bytes
        + struct.pack("!H", target_port)
    )
    writer.write(req)
    await writer.drain()
    reply = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    if reply[1] != 0x00:
        raise ConnectionError(f"SOCKS5 connect error code: {reply[1]}")
    atyp = reply[3]
    if atyp == 0x01:
        await asyncio.wait_for(reader.readexactly(6), timeout=timeout)
    elif atyp == 0x03:
        ln = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
        await asyncio.wait_for(reader.readexactly(ln + 2), timeout=timeout)
    elif atyp == 0x04:
        await asyncio.wait_for(reader.readexactly(18), timeout=timeout)


class AsyncSMTPVerifier:
    """Zero-send SMTP probe performing EHLO -> MAIL FROM -> RCPT TO -> QUIT."""

    def __init__(
        self,
        helo_domain: str = "verifier.internal",
        mail_from: str = "probe@verifier.internal",
        smtp_port: int = 25,
        connector: Optional[TransportConnector] = None,
    ) -> None:
        self.helo_domain = helo_domain
        self.mail_from = mail_from
        self.smtp_port = smtp_port
        self._connector = connector or default_tcp_or_socks_connect

    async def verify_mailbox(
        self,
        email: str,
        mx_host: str,
        proxy_url: Optional[str] = None,
        timeout: float = 5.0,
        check_catch_all: bool = True,
    ) -> SMTPVerificationResult:
        """Probe mailbox deliverability without transmitting DATA payload."""
        domain = email.split("@", 1)[1].lower()
        reader: Optional[asyncio.StreamReader] = None
        writer: Optional[asyncio.StreamWriter] = None

        try:
            reader, writer = await self._connector(mx_host, self.smtp_port, proxy_url, timeout)
            banner_code, banner_msg = await self._read_smtp_response(reader, timeout)
            if banner_code not in {220}:
                return SMTPVerificationResult(
                    deliverable=None,
                    smtp_code=banner_code,
                    banner=banner_msg,
                    reason=f"UNEXPECTED_BANNER_{banner_code}",
                )

            ehlo_code, ehlo_msg = await self._send_command(reader, writer, f"EHLO {self.helo_domain}", timeout)
            if ehlo_code >= 500:
                ehlo_code, ehlo_msg = await self._send_command(reader, writer, f"HELO {self.helo_domain}", timeout)
            if ehlo_code != 250:
                return SMTPVerificationResult(
                    deliverable=None,
                    smtp_code=ehlo_code,
                    banner=banner_msg,
                    reason=f"EHLO_REJECTED:{ehlo_msg}",
                )

            mail_code, mail_msg = await self._send_command(
                reader, writer, f"MAIL FROM:<{self.mail_from}>", timeout
            )
            if mail_code != 250:
                return SMTPVerificationResult(
                    deliverable=None,
                    smtp_code=mail_code,
                    banner=banner_msg,
                    reason=f"MAIL_FROM_REJECTED:{mail_msg}",
                )

            rcpt_code, rcpt_msg = await self._send_command(reader, writer, f"RCPT TO:<{email}>", timeout)

            if rcpt_code in {250, 251}:
                is_catch_all = False
                if check_catch_all:
                    probe_addr = f"catchall_probe_{secrets.token_hex(6)}@{domain}"
                    ca_code, _ = await self._send_command(reader, writer, f"RCPT TO:<{probe_addr}>", timeout)
                    is_catch_all = ca_code in {250, 251}
                await self._safe_quit(reader, writer, timeout)
                return SMTPVerificationResult(
                    deliverable=True,
                    is_catch_all=is_catch_all,
                    smtp_code=rcpt_code,
                    banner=banner_msg,
                    reason="CATCH_ALL_ACCEPTED" if is_catch_all else "MAILBOX_EXISTS",
                )

            await self._safe_quit(reader, writer, timeout)

            if 400 <= rcpt_code < 500:
                return SMTPVerificationResult(
                    deliverable=None,
                    smtp_code=rcpt_code,
                    banner=banner_msg,
                    reason=f"TEMP_FAIL_GREYLIST:{rcpt_msg}",
                    greylisted=True,
                )

            return SMTPVerificationResult(
                deliverable=False,
                smtp_code=rcpt_code,
                banner=banner_msg,
                reason=f"MAILBOX_REJECTED:{rcpt_msg}",
            )

        except (asyncio.TimeoutError, TimeoutError):
            return SMTPVerificationResult(deliverable=None, reason="SMTP_TIMEOUT")
        except (ConnectionRefusedError, OSError) as exc:
            return SMTPVerificationResult(deliverable=None, reason=f"SMTP_CONNECT_ERROR:{type(exc).__name__}")
        except Exception as exc:
            return SMTPVerificationResult(deliverable=None, reason=f"SMTP_PROTOCOL_ERROR:{exc}")
        finally:
            if writer is not None:
                writer.close()

    async def _send_command(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        command: str,
        timeout: float,
    ) -> Tuple[int, str]:
        writer.write(f"{command}\r\n".encode("utf-8"))
        await writer.drain()
        return await self._read_smtp_response(reader, timeout)

    async def _read_smtp_response(self, reader: asyncio.StreamReader, timeout: float) -> Tuple[int, str]:
        lines = []
        code = 0
        while True:
            raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not raw:
                raise ConnectionError("SMTP connection closed unexpectedly")
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(line)
            if len(line) >= 3 and line[:3].isdigit():
                code = int(line[:3])
                # Multiline SMTP replies use '-' after status code; final line uses ' ' or nothing
                if len(line) == 3 or line[3] == " ":
                    break
            else:
                break
        return code, " | ".join(lines)

    async def _safe_quit(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float,
    ) -> None:
        try:
            await self._send_command(reader, writer, "QUIT", min(timeout, 1.5))
        except Exception:
            pass
