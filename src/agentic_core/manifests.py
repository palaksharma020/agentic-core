# SPDX-License-Identifier: Apache-2.0
"""Signed tool manifests and description pinning: the tools an agent may use are exactly the ones that were
reviewed, as they were when they were reviewed (tool poisoning and "rug pulls").

An MCP server describes its tools at run time (name, description, input schema), and clients show those
descriptions to the model. A description changed after review is an instruction channel into the model, and
a changed schema changes what the tool accepts. So:

    pin(tool)        SHA-256 of the canonical JSON of {name, description, input_schema}: any change, even an
                     invisible character, changes the pin
    sign_manifest    a reviewer signs {format, issuer, audience, version, issued_at, tools: {name: pin}}
    verify_manifest  the signature is checked against trusted public keys before any pin is believed; then the
                     audience (which server it is for) and a minimum version (no rollback to an older one)
    check_pins       the tools a server offers now, against the manifest: trusted, drifted (pin differs, or
                     the tool can't be pinned), duplicated (offered more than once), unlisted, missing
    PinnedTools      the gateway's view; .visible(offered) returns exactly the trusted descriptors

Failure is per tool: a drifted, duplicated or unlisted tool is disabled and the others keep working. A
manifest that doesn't verify (tampered, unknown key, wrong audience, rolled back, malformed) trusts nothing.

Canonical JSON (canonical_json), so a port in another language computes the same pins and signatures:
objects with keys sorted by UTF-16 code units (as RFC 8785), no whitespace, strings as ASCII with every
non-ASCII or control character written as a lowercase \\uXXXX escape (surrogate pairs for astral characters),
integers in plain decimal; floats, NaN and non-JSON values are refused. tests/vectors/manifests.json holds
the expected canonical bytes. Signing is a port (the audit trail's Signer); adapters.ed25519 provides Ed25519.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from agentic_core.audit import Signer

FORMAT = "agentic-core/tool-manifest@1"
_PIN = re.compile(r"[0-9a-f]{64}")


class ManifestInvalid(Exception):
    """The manifest can't be trusted: bad signature, unknown key, wrong format or malformed content."""


class NotCanonical(ValueError):
    """The value has no canonical form (a float, NaN, or a non-JSON type)."""


def _string(text: str) -> str:
    # json.dumps with ensure_ascii escapes every non-ASCII and control character as lowercase \uXXXX, writes
    # astral characters as surrogate pairs and keeps lone surrogates as escapes (never an encoding error).
    return json.dumps(text, ensure_ascii=True)


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise NotCanonical("object keys must be strings")
        keys = sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(f"{_string(k)}:{_encode(value[k])}" for k in keys) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(v) for v in value) + "]"
    raise NotCanonical(
        f"{type(value).__name__} has no canonical form here (floats are not allowed)"
    )


def canonical_json(value: Any) -> bytes:
    return _encode(value).encode("ascii")


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
    """Raises NotCanonical for content with no canonical form; check_pins treats that tool as drifted."""
    return hashlib.sha256(canonical_json(tool.body())).hexdigest()


@dataclass(frozen=True)
class ToolManifest:
    issuer: str
    audience: str  # which tool server this manifest is for
    version: int  # increases with every signing; verifiers refuse versions below their minimum
    issued_at: str  # ISO 8601, informational
    tools: Mapping[str, str]  # tool name -> pin

    def body(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "issuer": self.issuer,
            "audience": self.audience,
            "version": self.version,
            "issued_at": self.issued_at,
            "tools": dict(self.tools),
        }

    @classmethod
    def of(
        cls,
        issuer: str,
        audience: str,
        version: int,
        issued_at: str,
        tools: Iterable[ToolDescriptor],
    ) -> ToolManifest:
        tools = list(tools)
        names = Counter(t.name for t in tools)
        duplicated = sorted(n for n, c in names.items() if c > 1)
        if duplicated:
            raise ValueError(f"tools offered more than once can't be signed: {duplicated}")
        return cls(issuer, audience, version, issued_at, {t.name: pin(t) for t in tools})


def sign_manifest(manifest: ToolManifest, signer: Signer) -> dict[str, Any]:
    """The signed manifest as a JSON-ready dict: {"manifest": body, "key_id": ..., "signature": ...}."""
    body = manifest.body()
    return {
        "manifest": body,
        "key_id": signer.key_id,
        "signature": signer.sign(canonical_json(body)),
    }


def verify_manifest(
    signed: Mapping[str, Any] | str,
    verify_signature: Callable[[str, bytes, str], bool],
    *,
    audience: str | None = None,
    min_version: int = 1,
) -> ToolManifest:
    """Check the signature over the canonical manifest body, then its shape, audience and version.
    Raises ManifestInvalid."""
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
    try:
        message = canonical_json(body)
    except NotCanonical as exc:
        raise ManifestInvalid(f"manifest has no canonical form: {exc}") from None
    if not verify_signature(key_id, message, signature):
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
    if version < min_version:
        raise ManifestInvalid(
            f"manifest version {version} is older than the minimum {min_version} (rollback)"
        )
    if audience is not None and body.get("audience") != audience:
        raise ManifestInvalid(f"manifest is for {body.get('audience')!r}, not {audience!r}")
    return ToolManifest(
        str(body.get("issuer", "")),
        str(body.get("audience", "")),
        version,
        str(body.get("issued_at", "")),
        dict(tools),
    )


@dataclass(frozen=True)
class PinReport:
    trusted: Mapping[str, str]  # name -> pin, for tools offered once with the signed pin
    drifted: Mapping[str, tuple[str, str]]  # name -> (pinned, now); now is "" if it can't be pinned
    duplicated: frozenset[str]  # offered more than once: never trusted
    unlisted: frozenset[str]  # offered by the server, not in the manifest
    missing: frozenset[str]  # in the manifest, not offered

    @property
    def clean(self) -> bool:
        return not self.drifted and not self.duplicated and not self.unlisted


def _safe_pin(tool: ToolDescriptor) -> str:
    try:
        return pin(tool)
    except NotCanonical:
        return ""


def check_pins(manifest: ToolManifest, offered: Iterable[ToolDescriptor]) -> PinReport:
    offered = list(offered)
    counts = Counter(t.name for t in offered)
    duplicated = frozenset(n for n, c in counts.items() if c > 1)
    now = {t.name: _safe_pin(t) for t in offered if t.name not in duplicated}
    return PinReport(
        trusted={n: p for n, p in now.items() if p and manifest.tools.get(n) == p},
        drifted={
            n: (manifest.tools[n], p)
            for n, p in now.items()
            if n in manifest.tools and manifest.tools[n] != p
        },
        duplicated=duplicated,
        unlisted=frozenset(n for n in counts if n not in manifest.tools),
        missing=frozenset(n for n in manifest.tools if n not in counts),
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
        return frozenset(self.report.trusted) if self.report else frozenset()

    def visible(self, offered: Sequence[ToolDescriptor]) -> list[ToolDescriptor]:
        """The descriptors that may be shown to the model: trusted name *and* matching pin, so a second,
        different descriptor under a trusted name never gets through."""
        if self.report is None:
            return []
        return [t for t in offered if self.report.trusted.get(t.name) == _safe_pin(t) != ""]

    def check(self, tool: str) -> tuple[bool, str]:
        if self.report is None:
            return False, f"tool manifest rejected: {self.failure}"
        if tool in self.report.trusted:
            return True, ""
        if tool in self.report.duplicated:
            return False, f"tool {tool!r} is offered more than once"
        if tool in self.report.drifted:
            if not self.report.drifted[tool][1]:
                return False, f"tool {tool!r} has content that can't be pinned"
            return False, f"tool {tool!r} changed since its manifest was signed (pin mismatch)"
        return False, f"tool {tool!r} is not in the signed tool manifest"
