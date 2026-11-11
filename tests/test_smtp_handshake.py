"""Integration tests for AsyncSMTPVerifier against a real loopback TCP SMTP server."""

import asyncio

from gtm_verifier.smtp_handshake import AsyncSMTPVerifier


async def _start_mock_smtp(mode: str = "standard"):
    """Launch an ephemeral asyncio TCP server simulating SMTP responses."""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"220 mock-mx.local ESMTP Postfix\r\n")
        await writer.drain()
        while True:
            line = await reader.readline()
            if not line:
                break
            cmd = line.decode("utf-8", errors="ignore").strip()
            upper = cmd.upper()
            if upper.startswith(("EHLO", "HELO")):
                writer.write(b"250-mock-mx.local\r\n250 PIPELINING\r\n")
            elif upper.startswith("MAIL FROM"):
                writer.write(b"250 2.1.0 Ok\r\n")
            elif upper.startswith("RCPT TO"):
                if mode == "catchall":
                    writer.write(b"250 2.1.5 Ok\r\n")
                elif mode == "greylist":
                    writer.write(b"450 4.2.0 Greylisted, try again later\r\n")
                elif "missing@" in cmd or "catchall_probe_" in cmd:
                    writer.write(b"550 5.1.1 User unknown in virtual mailbox table\r\n")
                else:
                    writer.write(b"250 2.1.5 Ok\r\n")
            elif upper.startswith("QUIT"):
                writer.write(b"221 2.0.0 Bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"502 Command not implemented\r\n")
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


def test_smtp_valid_and_invalid_mailbox() -> None:
    async def _run() -> None:
        server, port = await _start_mock_smtp("standard")
        try:
            verifier = AsyncSMTPVerifier(smtp_port=port)
            valid_res = await verifier.verify_mailbox("david@example.com", mx_host="127.0.0.1")
            assert valid_res.deliverable is True
            assert valid_res.is_catch_all is False
            assert valid_res.smtp_code == 250

            invalid_res = await verifier.verify_mailbox("missing@example.com", mx_host="127.0.0.1")
            assert invalid_res.deliverable is False
            assert invalid_res.smtp_code == 550
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_run())


def test_smtp_catch_all_detection() -> None:
    async def _run() -> None:
        server, port = await _start_mock_smtp("catchall")
        try:
            verifier = AsyncSMTPVerifier(smtp_port=port)
            res = await verifier.verify_mailbox("anyone@catchall.io", mx_host="127.0.0.1")
            assert res.deliverable is True
            assert res.is_catch_all is True
            assert res.reason == "CATCH_ALL_ACCEPTED"
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_run())


def test_smtp_greylist_detection() -> None:
    async def _run() -> None:
        server, port = await _start_mock_smtp("greylist")
        try:
            verifier = AsyncSMTPVerifier(smtp_port=port)
            res = await verifier.verify_mailbox("lead@greylist.io", mx_host="127.0.0.1")
            assert res.deliverable is None
            assert res.greylisted is True
            assert res.smtp_code == 450
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_run())
