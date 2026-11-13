"""Bind an approved release to exactly one Standard workflow execution."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Release:
    commit: str
    image_digest: str
    approval_id: str
    account: str
    campaign: str
    kind: str

    def __post_init__(self) -> None:
        if (
            not re.fullmatch(r"(?!0{40})[a-f0-9]{40}", self.commit)
            or not re.fullmatch(r"sha256:(?!0{64})[a-f0-9]{64}", self.image_digest)
            or not re.fullmatch(r"[A-Za-z0-9-]{16,64}", self.approval_id)
            or not re.fullmatch(r"(?!0{12})[0-9]{12}", self.account)
            or not re.fullmatch(r"[a-zA-Z0-9-]{1,64}", self.campaign)
            or self.kind not in {"ecs", "ota"}
        ):
            raise ValueError("Invalid release identity")

    def execution_identity(self, approved: Release) -> tuple[str, str]:
        """Use the same name for every use of an approval, including corrupted input."""
        if self != approved:
            raise ValueError("Release differs from the trusted approval")
        name = "day42-" + hashlib.sha256(self.approval_id.encode()).hexdigest()
        return name, json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
