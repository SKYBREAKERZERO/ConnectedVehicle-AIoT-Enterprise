"""Loopback HTTP fault: consume a committed 200, drop it before any client response."""

from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from typing import Any


class HTTPResponseDropProxy:
    def __init__(self, upstream_port: int) -> None:
        self.upstream_port = upstream_port
        self.dropped = 0
        self.confirmed_status: str | None = None
        self.server: asyncio.Server | None = None
        self.tasks: set[asyncio.Task[Any]] = set()

    async def __aenter__(self) -> HTTPResponseDropProxy:
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0, limit=65536)
        self.url = "http://127.0.0.1:" + str(self.server.sockets[0].getsockname()[1])
        return self

    async def __aexit__(self, *args: object) -> None:
        assert self.server
        self.server.close()
        await self.server.wait_closed()
        if self.tasks:
            await asyncio.wait_for(asyncio.gather(*self.tasks, return_exceptions=True), 15)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task
        self.tasks.add(task)
        upstream: asyncio.StreamWriter | None = None
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            lines = head[:-4].split(b"\r\n")
            method, path, _ = lines[0].decode("ascii").split(" ")
            headers = {
                line.split(b":", 1)[0].lower(): line.split(b":", 1)[1].strip() for line in lines[1:]
            }
            length = int(headers.get(b"content-length", b"0"))
            if not 0 <= length <= 65536:
                raise ValueError("Fault proxy only accepts bounded test requests")
            body = await asyncio.wait_for(reader.readexactly(length), 10)
            target = (
                method == "POST"
                and path.endswith("/reports")
                and json.loads(body).get("status") == "succeeded"
            )
            request = (
                b"\r\n".join(
                    [
                        lines[0],
                        *[
                            line
                            for line in lines[1:]
                            if not line.lower().startswith(b"connection:")
                        ],
                        b"Connection: close",
                        b"",
                        b"",
                    ]
                )
                + body
            )
            response, upstream = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.upstream_port), 5
            )
            assert upstream is not None
            upstream.write(request)
            await upstream.drain()
            chunks = []
            size = 0
            while block := await asyncio.wait_for(response.read(65536), 10):
                size += len(block)
                if size > 64 * 1024**2:
                    raise ValueError("Fault proxy response quota exceeded")
                chunks.append(block)
            payload = b"".join(chunks)
            if target and self.dropped == 0 and payload.startswith(b"HTTP/1.1 200"):
                self.dropped += 1
                self.confirmed_status = payload.split(b"\r\n", 1)[0].decode()
                writer.transport.abort()
                return
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), 5)
        except (ConnectionError, asyncio.IncompleteReadError, TimeoutError):
            pass
        finally:
            if upstream:
                upstream.close()
                with suppress(ConnectionError):
                    await upstream.wait_closed()
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()
            self.tasks.discard(task)
