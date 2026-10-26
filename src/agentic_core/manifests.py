# SPDX-License-Identifier: Apache-2.0
"""Signed tool manifests and description pinning: the tools an agent may use are exactly the ones that were
reviewed, as they were when they were reviewed (tool poisoning and "rug pulls").

An MCP server describes its tools at run time (name, description, input schema), and clients show those
descriptions to the model. A description changed after review is an instruction channel into the model, and
a changed schema changes what the tool accepts. So:

    pin(tool)        SHA-256 of the canonical JSON of {name, description, input_schema}: any change, even an
                     invisible character, changes the pin
    sign_manifest    a reviewer signs {format, issuer, version, issued_at, tools: {name: pin}}
    verify_manifest  the signature is checked against trusted public keys before any pin is believed
    check_pins       the tools a server offers now, against the manifest: trusted, drifted (pin differs),
                     unlisted (not in the manifest), missing (in the manifest, not offered)
    PinnedTools      the gateway's view: only trusted tools may be shown to the model or called

Failure is per tool: a drifted or unlisted tool is disabled and the others keep working. A manifest that
doesn't verify (tampered, unknown key, malformed) trusts nothing.
Signing is a port (the audit trail's Signer); adapters.ed25519 provides Ed25519.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from agentic_core.audit import Signer, canonical

FORMAT = "agentic-core/tool-manifest@1"
_PIN = re.compile(r"[0-9a-f]{64}")


class ManifestInvalid(Exception):
    """The manifest can't be trusted: bad signature, unknown key, wrong format or malformed content."""


@dataclass(frozen=True)
class ToolDescriptor:
    """A tool as a server describes it to clients (MCP tools/list: name, description, inputSchema)."""

    name: str
    description: str
    input_schema: Mapping[str, Any] = field(default_factory=dict)

    def body(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": dict(self.input_schema),
        }


def pin(tool: ToolDescriptor) -> str:
    return hashlib.sha256(canonical(tool.body())).hexdigest()


@dataclass(frozen=True)
class ToolManifest:
    issuer: str
    version: int
    issued_at: str  # ISO 8601, informational
    tools: Mapping[str, str]  # tool name -> pin

    def body(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "issuer": self.issuer,
            "version": self.version,
            "issued_at": self.issued_at,
            "tools": dict(sorted(self.tools.items())),
        }

    @classmethod
    def of(
        cls, issuer: str, version: int, issued_at: str, tools: Iterable[ToolDescriptor]
    ) -> ToolManifest:
        return cls(issuer, version, issued_at, {t.name: pin(t) for t in tools})


def sign_manifest(manifest: ToolManifest, signer: Signer) -> dict[str, Any]:
    """The signed manifest as a JSON-ready dict: {"manifest": body, "key_id": ..., "signature": ...}."""
    body = manifest.body()
    return {"manifest": body, "key_id": signer.key_id, "signature": signer.sign(canonical(body))}


def verify_manifest(
    signed: Mapping[str, Any] | str, verify_signature: Callable[[str, bytes, str], bool]
) -> ToolManifest:
    """Check the signature over the canonical manifest body, then its shape. Raises ManifestInvalid."""
    try:
        data = json.loads(signed) if isinstance(signed, str) else signed
        body, key_id, signature = data["manifest"], data["key_id"], data["signature"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ManifestInvalid(f"not a signed manifest ({type(exc).__name__})") from None
    if (
        not isinstance(body, Mapping)
        or not isinstance(key_id, str)
        or not isinstance(signature, str)
    ):
        raise ManifestInvalid("not a signed manifest (wrong types)")
    if not verify_signature(key_id, canonical(body), signature):
        raise ManifestInvalid(
            f"signature does not verify with key {key_id!r} (tampered or unknown key)"
        )
    if body.get("format") != FORMAT:
        raise ManifestInvalid(f"unsupported manifest format {body.get('format')!r}")
    tools = body.get("tools")
    if not isinstance(tools, Mapping) or not all(
        isinstance(k, str) and isinstance(v, str) and _PIN.fullmatch(v) for k, v in tools.items()
    ):
        raise ManifestInvalid("tools must map names to SHA-256 pins")
    version = body.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ManifestInvalid("version must be an integer")
    return ToolManifest(
        str(body.get("issuer", "")), version, str(body.get("issued_at", "")), dict(tools)
    )


@dataclass(frozen=True)
class PinReport:
    trusted: frozenset[str]
    drifted: Mapping[str, tuple[str, str]]  # name -> (pinned, now)
    unlisted: frozenset[str]  # offered by the server, not in the manifest
    missing: frozenset[str]  # in the manifest, not offered

    @property
    def clean(self) -> bool:
        return not self.drifted and not self.unlisted


def check_pins(manifest: ToolManifest, offered: Iterable[ToolDescriptor]) -> PinReport:
    now = {t.name: pin(t) for t in offered}
    drifted = {
        name: (manifest.tools[name], p)
        for name, p in now.items()
        if name in manifest.tools and manifest.tools[name] != p
    }
    return PinReport(
        trusted=frozenset(n for n, p in now.items() if manifest.tools.get(n) == p),
        drifted=drifted,
        unlisted=frozenset(n for n in now if n not in manifest.tools),
        missing=frozenset(n for n in manifest.tools if n not in now),
    )


@dataclass(frozen=True)
class PinnedTools:
    """What the gateway may trust. Build it with from_report, or untrusted(reason) when the manifest
    itself failed (then every tool is refused with that reason)."""

    report: PinReport | None
    failure: str = ""

    @classmethod
    def from_report(cls, report: PinReport) -> PinnedTools:
        return cls(report)

    @classmethod
    def untrusted(cls, reason: str) -> PinnedTools:
        return cls(None, reason)

    @property
    def trusted(self) -> frozenset[str]:
        return self.report.trusted if self.report else frozenset()

    def check(self, tool: str) -> tuple[bool, str]:
        if self.report is None:
            return False, f"tool manifest rejected: {self.failure}"
        if tool in self.report.trusted:
            return True, ""
        if tool in self.report.drifted:
            return False, f"tool {tool!r} changed since its manifest was signed (pin mismatch)"
        return False, f"tool {tool!r} is not in the signed tool manifest"
