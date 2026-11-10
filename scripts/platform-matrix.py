#!/usr/bin/env python3
"""Generate the cross-platform capability matrix from code and evidence.

The capability inventory is `crates/aevan-core/src/capabilities.rs`. The
implementation state of every capability x platform is derived by reading the
modules named there. The `verified` column is read only from
`docs/platform-evidence.toml`; it is never inferred from code.

Run with no arguments to print the table and write `docs/PLATFORM-MATRIX.md`.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPABILITIES_RS = ROOT / "crates" / "aevan-core" / "src" / "capabilities.rs"
EVIDENCE_TOML = ROOT / "docs" / "platform-evidence.toml"
MATRIX_DOC = ROOT / "docs" / "PLATFORM-MATRIX.md"

PLATFORMS = ("windows", "macos", "linux")
PLATFORM_LABELS = {"windows": "Windows", "macos": "macOS", "linux": "Linux"}
IMPLEMENTATION_STATES = ("implemented", "stub", "absent")
EVIDENCE_STATES = ("verified-live", "compile-only")

# Non-Rust packaging artifacts are real when they exist and do not only say
# that the platform is unsupported.
NON_RUST_IMPLEMENTED = True

# Tokens that indicate a real platform implementation inside a cfg block.
# They deliberately exclude no-op constructs such as `Subscription::none()`.
IMPLEMENTATION_TOKENS = (
    "Command::new",
    "std::process",
    "std::fs",
    "notify_rust",
    "notify-rust",
    "SMAppService",
    "NamedPipe",
    "NamedPipeServer",
    "UnixListener",
    "UnixStream",
    "libc::",
    "Wintun",
    "wintun",
    "netsh",
    "networksetup",
    "resolvectl",
    "resolvconf",
    "schtasks",
    "launchctl",
    "systemctl",
    "TrayIcon",
    "NSStatusItem",
    "tao",
    "objc2",
    "UNUser",
    "UserNotifications",
    "install_gui",
    "install_login_item",
    "remove_login_item",
    "login_item_state",
    "register",
    "unregister",
    "PlatformApplier",
    "LinuxTunDevice",
    "UtunDevice",
    "WindowsTunDevice",
    "create_server",
    "OpenOptions",
    "File::",
    "fs::",
    "include_bytes",
    "setsockopt",
    "ioctl",
    "spawn(",
    "exec",
    "CustomAction",
    "ServiceInstall",
    "ExecStart",
    "systemd",
    "wix",
    "pkgbuild",
    "productbuild",
)

UNSUPPORTED_TOKENS = (
    "Unsupported",
    "unsupported(",
    "not implemented",
    "not supported",
)


@dataclass(frozen=True)
class Capability:
    id: str
    title: str
    modules: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class Evidence:
    capability: str
    platform: str
    state: str
    source: str


def fail(message: str) -> None:
    print(f"platform-matrix: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")


def strip_rust_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def brace_depths(text: str) -> list[int]:
    depths: list[int] = []
    depth = 0
    for character in text:
        depths.append(depth)
        if character == "{":
            depth += 1
        elif character == "}":
            depth = max(0, depth - 1)
    return depths


def cfg_attributes(text: str) -> list[tuple[int, int, str]]:
    """Return (attribute_start, attribute_end, expression) for every cfg."""
    attributes: list[tuple[int, int, str]] = []
    needle = "#[cfg("
    cursor = 0
    while True:
        start = text.find(needle, cursor)
        if start < 0:
            break
        inner = start + len(needle)
        depth = 1
        position = inner
        while position < len(text) and depth:
            if text[position] == "(":
                depth += 1
            elif text[position] == ")":
                depth -= 1
            position += 1
        if depth:
            break
        expression = text[inner : position - 1]
        end = position
        if text[end : end + 1] == "]":
            end += 1
        attributes.append((start, end, expression))
        cursor = end
    return attributes


class CfgError(ValueError):
    pass


def tokenize_cfg(expression: str) -> list[str]:
    pattern = re.compile(
        r'\s*(?:(?P<string>"(?:[^"\\]|\\.)*")|(?P<ident>[A-Za-z_][A-Za-z0-9_]*)|(?P<op>[(),=]))'
    )
    result: list[str] = []
    for match in pattern.finditer(expression):
        value = match.group(0).strip()
        if value:
            result.append(value)
    if not result:
        raise CfgError(f"empty cfg expression: {expression!r}")
    return result


class CfgParser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.position = 0

    def peek(self) -> str | None:
        if self.position >= len(self.tokens):
            return None
        return self.tokens[self.position]

    def take(self, expected: str | None = None) -> str:
        token = self.peek()
        if token is None:
            raise CfgError("unexpected end of cfg expression")
        if expected is not None and token != expected:
            raise CfgError(f"expected {expected!r}, got {token!r}")
        self.position += 1
        return token

    def parse(self):
        token = self.peek()
        if token is None:
            raise CfgError("empty cfg expression")
        if token == "not":
            self.take()
            self.take("(")
            value = self.parse()
            self.take(")")
            return ("not", value)
        if token in ("any", "all"):
            self.take()
            self.take("(")
            values = []
            if self.peek() != ")":
                while True:
                    values.append(self.parse())
                    if self.peek() == ",":
                        self.take(",")
                        continue
                    break
            self.take(")")
            return (token, values)
        identifier = self.take()
        if self.peek() == "=":
            self.take("=")
            value = self.take()
            if not value.startswith('"'):
                raise CfgError(f"expected string after '=', got {value!r}")
            return ("=", identifier, value.strip('"'))
        return ("ident", identifier)


def evaluate_cfg(expression: str, platform: str) -> bool:
    parser = CfgParser(tokenize_cfg(expression))

    def evaluate(node):
        kind = node[0]
        if kind == "not":
            return not evaluate(node[1])
        if kind == "any":
            return any(evaluate(value) for value in node[1])
        if kind == "all":
            return all(evaluate(value) for value in node[1])
        if kind == "=":
            _, key, value = node
            if key == "target_os":
                return value == platform
            if key == "target_family":
                return value == "unix" and platform in ("macos", "linux")
            return False
        if kind == "ident":
            identifier = node[1]
            if identifier == "windows":
                return platform == "windows"
            if identifier == "unix":
                return platform in ("macos", "linux")
            if identifier == "test":
                return False
            return False
        raise CfgError(f"unknown cfg node {node!r}")

    return evaluate(parser.parse())


def contains_any(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


def classify_module(path: Path, platform: str) -> str:
    if not path.exists():
        return "absent"
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix != ".rs":
        if not text.strip():
            return "absent"
        if contains_any(text.lower(), tuple(token.lower() for token in UNSUPPORTED_TOKENS)):
            if not contains_any(text, IMPLEMENTATION_TOKENS):
                return "stub"
        return "implemented" if NON_RUST_IMPLEMENTED else "absent"

    text = strip_rust_comments(text)
    attributes = [
        attribute
        for attribute in cfg_attributes(text)
        if not re.fullmatch(r"\s*test\s*", attribute[2])
    ]
    if not attributes:
        if contains_any(text, UNSUPPORTED_TOKENS) and not contains_any(
            text, IMPLEMENTATION_TOKENS
        ):
            return "stub"
        return "implemented"

    depths = brace_depths(text)
    saw_stub = False
    saw_implementation = False
    saw_true = False
    for index, (start, end, expression) in enumerate(attributes):
        try:
            matches = evaluate_cfg(expression, platform)
        except CfgError:
            matches = False
        if not matches:
            continue
        saw_true = True
        region_end = len(text)
        current_depth = depths[start]
        for later_start, _, _ in attributes[index + 1 :]:
            if depths[later_start] <= current_depth:
                region_end = later_start
                break
        block = text[end:region_end]
        has_unsupported = contains_any(block, UNSUPPORTED_TOKENS)
        has_implementation = contains_any(block, IMPLEMENTATION_TOKENS)
        if has_implementation:
            saw_implementation = True
        elif has_unsupported:
            saw_stub = True

    if saw_implementation:
        return "implemented"
    if saw_stub:
        return "stub"
    if saw_true:
        return "absent"
    return "absent"


def classify_cell(capability: Capability, platform: str) -> str:
    modules = capability.modules.get(platform, ())
    if not modules:
        return "absent"
    states = [classify_module(ROOT / module, platform) for module in modules]
    if "implemented" in states:
        return "implemented"
    if "stub" in states:
        return "stub"
    return "absent"


def parse_capabilities() -> list[Capability]:
    text = read_text(CAPABILITIES_RS)
    marker = "pub const CAPABILITIES"
    start = text.find(marker)
    if start < 0:
        fail(f"{CAPABILITIES_RS.relative_to(ROOT)} has no CAPABILITIES list")
    region = text[start:]
    end = region.find("\n];")
    if end < 0:
        fail("cannot find the end of the CAPABILITIES list")
    region = region[:end]

    capabilities: list[Capability] = []
    for block in re.findall(r"Capability\s*\{(.*?)\n\s*\}", region, flags=re.S):
        identifier = re.search(r'id:\s*"([^"]+)"', block)
        title = re.search(r'title:\s*"([^"]+)"', block)
        if not identifier or not title:
            fail("a Capability entry is missing id or title")
        modules: dict[str, tuple[str, ...]] = {}
        for platform in PLATFORMS:
            field = re.search(rf"{platform}:\s*&\[(.*?)\]", block, flags=re.S)
            if not field:
                fail(f"{identifier.group(1)} has no {platform} module list")
            modules[platform] = tuple(re.findall(r'"([^"]+)"', field.group(1)))
        capabilities.append(
            Capability(
                id=identifier.group(1),
                title=title.group(1),
                modules=modules,
            )
        )

    if not capabilities:
        fail("no capabilities found")
    ids = [capability.id for capability in capabilities]
    if len(ids) != len(set(ids)):
        fail("duplicate capability ids")
    return capabilities


def parse_evidence(capabilities: list[Capability]) -> dict[tuple[str, str], Evidence]:
    if not EVIDENCE_TOML.exists():
        return {}
    try:
        import tomllib
    except ImportError:
        fail("Python 3.11 or newer is required (tomllib)")
    try:
        document = tomllib.loads(read_text(EVIDENCE_TOML))
    except tomllib.TOMLDecodeError as error:
        fail(f"invalid docs/platform-evidence.toml: {error}")

    known = {capability.id for capability in capabilities}
    entries: dict[tuple[str, str], Evidence] = {}
    for raw in document.get("evidence", []):
        for field in ("capability", "platform", "state", "source"):
            if field not in raw:
                fail(f"evidence entry is missing {field!r}: {raw!r}")
        capability = str(raw["capability"])
        platform = str(raw["platform"])
        state = str(raw["state"])
        source = str(raw["source"])
        if capability not in known:
            fail(f"evidence names unknown capability {capability!r}")
        if platform not in PLATFORMS:
            fail(f"evidence names unknown platform {platform!r}")
        if state not in EVIDENCE_STATES:
            fail(
                f"evidence for {capability}/{platform} has state {state!r}; "
                f"expected one of {', '.join(EVIDENCE_STATES)}"
            )
        key = (capability, platform)
        if key in entries:
            fail(f"duplicate evidence for {capability}/{platform}")
        entries[key] = Evidence(capability, platform, state, source)
    return entries


def escape_markdown(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_matrix(
    capabilities: list[Capability],
    evidence: dict[tuple[str, str], Evidence],
) -> str:
    lines = [
        "# Platform capability matrix",
        "",
        "Every cell is **implemented**, **stub** or **absent**, and **compile-only** means the code exists but nobody has run that capability on that operating system.",
        "",
        "This file is generated by `scripts/platform-matrix.py`. Edit the capability list, "
        "`docs/platform-evidence.toml` or `docs/platform-gaps.toml`, then regenerate it; do "
        "not hand-edit the table. Code state is derived from the modules named in "
        "`crates/aevan-core/src/capabilities.rs`. The **Verified** column is populated only "
        "from `docs/platform-evidence.toml` and is never inferred from code.",
        "",
        "| Capability | Windows | macOS | Linux | Verified |",
        "| --- | --- | --- | --- | --- |",
    ]

    for capability in capabilities:
        cells = [capability.title]
        for platform in PLATFORMS:
            cells.append(classify_cell(capability, platform))
        verified: list[str] = []
        for platform in PLATFORMS:
            entry = evidence.get((capability.id, platform))
            if entry is not None:
                verified.append(
                    f"{PLATFORM_LABELS[platform]}: **{entry.state}** "
                    f"({escape_markdown(entry.source)})"
                )
        cells.append("<br>".join(verified) if verified else "—")
        lines.append("| " + " | ".join(cells) + " |")

    lines.extend(
        [
            "",
            "## Legend",
            "",
            "- **implemented** — the named module has a real implementation for that platform.",
            "- **stub** — the platform compiles a cfg block that only returns `Unsupported`.",
            "- **absent** — there is no cfg-gated implementation for that platform.",
            "- **verified-live** — a checked-in evidence entry records an actual run on that OS.",
            "- **compile-only** — the code compiles, but no one has run the capability on that OS.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    capabilities = parse_capabilities()
    evidence = parse_evidence(capabilities)
    document = render_matrix(capabilities, evidence)
    print(document)
    MATRIX_DOC.write_text(document, encoding="utf-8", newline="\n")
    print(f"wrote {MATRIX_DOC.relative_to(ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
