from __future__ import annotations

import asyncio
import json
import logging
import socket
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID


@dataclass(frozen=True)
class Frame:
    """Classical CAN ID/data carried by a loopback UDP simulation envelope.

    UUID correlation is harness metadata, not bytes on a physical CAN bus.
    """

    command_id: UUID
    arbitration_id: int
    data: bytes

    def encode(self) -> bytes:
        if self.arbitration_id not in (0x100, 0x180) or not 1 <= len(self.data) <= 8:
            raise ValueError("invalid_can_frame")
        return json.dumps(
            {
                "command_id": str(self.command_id),
                "arbitration_id": self.arbitration_id,
                "data": self.data.hex(),
            },
            separators=(",", ":"),
        ).encode()

    @classmethod
    def decode(cls, raw: bytes) -> Frame:
        if len(raw) > 256:
            raise ValueError("oversized_can_envelope")
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"command_id", "arbitration_id", "data"}:
            raise ValueError("invalid_can_envelope")
        if (
            type(value["arbitration_id"]) is not int
            or not isinstance(value["command_id"], str)
            or not isinstance(value["data"], str)
        ):
            raise ValueError("invalid_can_id")
        frame = cls(
            UUID(value["command_id"]), value["arbitration_id"], bytes.fromhex(value["data"])
        )
        frame.encode()
        return frame


def command_frame(command_id: UUID, opcode: int, expires: int) -> Frame:
    return Frame(command_id, 0x100, struct.pack("!BI", opcode, expires))


def precise_command_frame(command_id: UUID, opcode: int, expires: datetime) -> Frame:
    if expires.tzinfo is None:
        raise ValueError("naive_command_expiry")
    delta = expires.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    microseconds = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    # Round up: the wire deadline must never expire before the source deadline.
    milliseconds = (microseconds + 999) // 1000
    if microseconds < 0 or not 0 <= milliseconds < 2**48:
        raise ValueError("invalid_command_expiry")
    return Frame(command_id, 0x100, bytes([opcode]) + milliseconds.to_bytes(6, "big"))


def decode_command(frame: Frame) -> tuple[int, float]:
    if frame.arbitration_id != 0x100:
        raise ValueError("invalid_command_frame")
    if len(frame.data) == 5:
        opcode, seconds = struct.unpack("!BI", frame.data)
        return opcode, float(seconds)
    if len(frame.data) == 7:
        return frame.data[0], int.from_bytes(frame.data[1:], "big") / 1000
    raise ValueError("invalid_command_frame")


class VirtualCAN:
    def __init__(self, local_port: int, peer_port: int) -> None:
        self.peer = ("127.0.0.1", peer_port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind(("127.0.0.1", local_port))
            self.socket.setblocking(False)
        except BaseException:
            self.socket.close()
            raise

    def close(self) -> None:
        self.socket.close()

    async def send(self, frame: Frame) -> None:
        encoded = frame.encode()
        try:
            await asyncio.get_running_loop().sock_sendto(self.socket, encoded, self.peer)
        except (ConnectionResetError, ConnectionRefusedError):
            # Durable callers keep their pending rows; the next attempt resends.
            logging.warning("virtual_can_peer_unavailable")

    async def receive(self) -> Frame:
        loop = asyncio.get_running_loop()
        while True:
            try:
                raw, sender = await loop.sock_recvfrom(self.socket, 1024)
            except (ConnectionResetError, ConnectionRefusedError):
                # UDP ICMP port-unreachable while the peer ECU is restarting.
                await asyncio.sleep(0.05)
                continue
            if sender != self.peer:
                continue
            try:
                return Frame.decode(raw)
            except (ValueError, TypeError, KeyError):
                continue
