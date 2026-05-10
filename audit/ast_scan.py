"""AST-based security scanner for Python packages.

Walks every .py file in a target directory, classifies imports + function
calls into the 8 audit dimensions defined in the project spec:

  1. Network egress (requests/httpx/urllib3 calls, hostnames, TLS posture)
  2. Subprocess / shell / eval / exec / dynamic imports
  3. Filesystem reads + writes
  4. Environment variable reads
  5. Stdin / stdout / stderr usage
  6. Inbound network (raw sockets, http servers, web frameworks)
  7. URL / header construction safety
  8. Declared dependencies (pyproject.toml or requirements.txt)

Pure stdlib. No LLM, no network, no third-party deps. Same input always
produces the same output — that's a deliberate design property; an audit
tool whose findings depend on time-of-day or remote data is not auditable
itself.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ── Pattern catalogs ────────────────────────────────────────────────────────
#
# Every dimension compiles down to "is this AST node a member of one of
# these named function calls?" We keep the catalogs as flat sets for fast
# membership checks. When you add a new pattern here, also extend the
# README's "what we detect" table.

_HTTP_CLIENT_FUNCS = {
    # requests
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.head", "requests.patch", "requests.options", "requests.request",
    "requests.Session.get", "requests.Session.post",
    # httpx
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
    "httpx.head", "httpx.patch", "httpx.request",
    "httpx.Client.get", "httpx.Client.post",
    "httpx.AsyncClient.get", "httpx.AsyncClient.post",
    # urllib
    "urllib.request.urlopen", "urlopen",
    # aiohttp
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
}

_SUBPROCESS_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "os.system", "os.popen", "os.spawnl", "os.spawnle", "os.spawnlp",
    "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.execl", "os.execle", "os.execlp", "os.execlpe", "os.execv",
    "os.execve", "os.execvp", "os.execvpe",
    "pty.spawn", "pexpect.spawn", "pexpect.run",
}

_DYNAMIC_EXEC_FUNCS = {"eval", "exec", "compile", "__import__"}

_FS_WRITE_FUNCS = {
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.rename",
    "os.renames", "os.replace", "os.mkdir", "os.makedirs", "os.chmod",
    "os.chown", "os.symlink", "os.link", "os.truncate",
    "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree",
    "shutil.move", "shutil.rmtree", "shutil.chown",
    "pathlib.Path.write_text", "pathlib.Path.write_bytes",
    "pathlib.Path.unlink", "pathlib.Path.rmdir", "pathlib.Path.mkdir",
    "pathlib.Path.rename", "pathlib.Path.replace", "pathlib.Path.chmod",
    "pathlib.Path.touch",
    "Path.write_text", "Path.write_bytes", "Path.unlink", "Path.rmdir",
    "Path.mkdir", "Path.rename", "Path.replace", "Path.chmod", "Path.touch",
}

_FS_READ_FUNCS = {
    "pathlib.Path.read_text", "pathlib.Path.read_bytes",
    "pathlib.Path.iterdir", "pathlib.Path.glob", "pathlib.Path.rglob",
    "Path.read_text", "Path.read_bytes",
    "os.listdir", "os.scandir", "os.walk",
    "glob.glob", "glob.iglob",
}

_ENV_READ_FUNCS = {"os.environ.get", "os.getenv"}

_STDIN_FUNCS = {"input", "sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines"}
_STDOUT_FUNCS = {"sys.stdout.write", "sys.stdout.flush"}
_STDERR_FUNCS = {"sys.stderr.write", "sys.stderr.flush"}

_INBOUND_FUNCS = {
    "socket.socket.bind", "socket.bind",
    "http.server.HTTPServer", "socketserver.TCPServer", "socketserver.UDPServer",
    "uvicorn.run", "hypercorn.run", "waitress.serve",
    "flask.Flask.run", "Flask.run",
    "fastapi.FastAPI",   # presence of a FastAPI() call is a strong signal
}

# Regex for hostnames in URL strings — catches both literal hostnames and
# the host portion of a fully-qualified URL.
_URL_HOST_RE = re.compile(r"https?://([^/:?#\s'\"]+)", re.I)


# Dimension 9 — string-content safety (tool descriptions, prompts, etc.)
#
# Added 2026-05-10 after a manual auditor flagged that mcp-audit was
# missing checks an experienced reviewer does naturally: scan tool
# descriptions for hidden instructions, zero-width unicode, and
# prompt-injection patterns. Pure regex + char-set detection — no LLM.
#
# Strategy: walk every string literal ≥ MIN_STR_LEN chars long, flag
# matches. False positives are possible (a doc string about prompt
# injection would match) but the rate is low enough to be acceptable
# v0.1; reviewer can verify each flagged site by inspection.

_ZERO_WIDTH_CHARS = (
    "​"  # ZERO WIDTH SPACE
    "‌"  # ZERO WIDTH NON-JOINER
    "‍"  # ZERO WIDTH JOINER
    "⁠"  # WORD JOINER
    "﻿"  # ZERO WIDTH NO-BREAK SPACE / BOM
    "‪"  # LEFT-TO-RIGHT EMBEDDING
    "‫"  # RIGHT-TO-LEFT EMBEDDING
    "‬"  # POP DIRECTIONAL FORMATTING
    "‭"  # LEFT-TO-RIGHT OVERRIDE
    "‮"  # RIGHT-TO-LEFT OVERRIDE
)

# Patterns that look like attempted prompt-injection inside what should
# be neutral metadata (tool descriptions, config strings). These are
# common jailbreak fragments — none of them have a legitimate place in
# a tool description.
_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore (?:all )?(?:previous|prior|earlier|above) (?:instructions?|directives?|commands?)", re.I),
    re.compile(r"ignore the (?:user|system|developer)", re.I),
    re.compile(r"disregard (?:previous|prior|all) (?:instructions?|directives?)", re.I),
    re.compile(r"system\s*[:\-]\s*(?:override|prompt|admin)", re.I),
    re.compile(r"\[\s*(?:system|admin|root|developer)\s*\]", re.I),
    re.compile(r"<\s*system\s*>", re.I),
    re.compile(r"override (?:safety|policy|rule|guideline|instruction)", re.I),
    re.compile(r"act as (?:if you (?:are|were)|though you (?:are|were))", re.I),
    re.compile(r"you (?:are|will be) (?:now |only )?(?:in )?(?:DAN|developer|debug|root|admin) mode", re.I),
]

# Only check strings at least this long — short strings are very unlikely
# to host meaningful injection or hidden content, and the false-positive
# rate goes up sharply on short strings (e.g., "ignore" is fine in
# general English).
_MIN_STR_LEN = 30


# ── Data classes ────────────────────────────────────────────────────────────

@dataclass
class CallSite:
    """One detected function call worth recording."""
    file: str
    line: int
    name: str          # canonical dotted name e.g. "requests.get"
    note: str = ""     # optional inline detail e.g. "verify=False" or "url=f-string"


@dataclass
class ScanResult:
    """All findings from a full scan, organized by dimension."""
    target_path: str
    files_scanned: int = 0
    lines_scanned: int = 0

    # Dimension 1 — network egress
    http_calls: list[CallSite] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    tls_disabled_calls: list[CallSite] = field(default_factory=list)

    # Dimension 2 — code-execution risks
    subprocess_calls: list[CallSite] = field(default_factory=list)
    dynamic_exec_calls: list[CallSite] = field(default_factory=list)

    # Dimension 3 — filesystem
    fs_write_calls: list[CallSite] = field(default_factory=list)
    fs_read_calls: list[CallSite] = field(default_factory=list)
    open_calls: list[CallSite] = field(default_factory=list)  # open() with mode

    # Dimension 4 — env vars
    env_reads: dict[str, list[CallSite]] = field(default_factory=dict)

    # Dimension 5 — stdio
    stdin_calls: list[CallSite] = field(default_factory=list)
    stdout_calls: list[CallSite] = field(default_factory=list)
    stderr_calls: list[CallSite] = field(default_factory=list)

    # Dimension 6 — inbound network
    inbound_calls: list[CallSite] = field(default_factory=list)

    # Dimension 7 — URL/header construction safety
    url_construction_warnings: list[CallSite] = field(default_factory=list)

    # Dimension 8 — dependencies
    dependencies: list[str] = field(default_factory=list)
    dep_source: str = ""  # "pyproject.toml" / "requirements.txt" / "(none)"

    # Dimension 9 — string-content safety (tool descriptions, prompts)
    zero_width_strings: list[CallSite] = field(default_factory=list)
    injection_pattern_strings: list[CallSite] = field(default_factory=list)


# ── AST helpers ─────────────────────────────────────────────────────────────

def _dotted_name(node: ast.AST) -> str:
    """Best-effort canonical dotted name for a call's func attr.

    `requests.get` → "requests.get"
    `httpx.AsyncClient().get` → "AsyncClient.get"  (lossy — instances strip)
    `_get` → "_get"
    `obj.method` → "method"  (when obj isn't a module reference)
    """
    if isinstance(node, ast.Attribute):
        parts = []
        cur: ast.AST | None = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _get_kwarg_value(call: ast.Call, kwname: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == kwname:
            return kw.value
    return None


def _is_falsey_constant(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _string_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _extract_url_arg(call: ast.Call) -> tuple[ast.AST | None, str]:
    """Return (url_arg_node, kind) for a requests/httpx call.

    kind is "literal" | "fstring" | "concat" | "name" | "unknown".
    """
    if not call.args and not call.keywords:
        return None, "unknown"
    url_node: ast.AST | None = None
    if call.args:
        url_node = call.args[0]
    if url_node is None:
        url_node = _get_kwarg_value(call, "url")
    if url_node is None:
        return None, "unknown"
    if isinstance(url_node, ast.Constant) and isinstance(url_node.value, str):
        return url_node, "literal"
    if isinstance(url_node, ast.JoinedStr):
        return url_node, "fstring"
    if isinstance(url_node, ast.BinOp) and isinstance(url_node.op, ast.Add):
        return url_node, "concat"
    if isinstance(url_node, ast.Name):
        return url_node, "name"
    return url_node, "unknown"


def _hosts_from_string(s: str) -> set[str]:
    return set(_URL_HOST_RE.findall(s or ""))


# ── The visitor ─────────────────────────────────────────────────────────────

class _Scanner(ast.NodeVisitor):
    """Walks one .py file, accumulates findings into `result`."""

    def __init__(self, result: ScanResult, file_path: str):
        self.r = result
        self.file = file_path

    def _site(self, node: ast.AST, name: str, note: str = "") -> CallSite:
        line = getattr(node, "lineno", 0) or 0
        return CallSite(file=self.file, line=line, name=name, note=note)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted_name(node.func)
        bare = name.split(".")[-1] if name else ""

        # Dynamic exec — eval / exec / compile / __import__
        if bare in _DYNAMIC_EXEC_FUNCS and "." not in name:
            # Only flag bare builtins, not e.g. `something.eval`
            self.r.dynamic_exec_calls.append(self._site(node, bare))

        # Subprocess / shell
        if name in _SUBPROCESS_FUNCS or any(name.endswith("." + sp.split(".")[-1]) for sp in _SUBPROCESS_FUNCS if sp.startswith("subprocess")):
            shell_kw = _get_kwarg_value(node, "shell")
            note = "shell=True" if isinstance(shell_kw, ast.Constant) and shell_kw.value is True else ""
            self.r.subprocess_calls.append(self._site(node, name, note))

        # HTTP client calls
        elif self._is_http_client_call(name):
            verify_kw = _get_kwarg_value(node, "verify")
            tls_off = _is_falsey_constant(verify_kw)
            url_node, url_kind = _extract_url_arg(node)
            url_str = _string_constant(url_node) if url_kind == "literal" else None
            if url_str:
                for h in _hosts_from_string(url_str):
                    self.r.hosts.add(h)
            elif url_kind == "fstring" and isinstance(url_node, ast.JoinedStr):
                # f-strings commonly include the host as a literal prefix:
                #   f"https://api.example.com/{path}"
                # The leading Constant in JoinedStr.values is that prefix.
                # Extract hosts from it. Doesn't help if the f-string starts
                # with a {var} (the jarvis-trading-mcp pattern) — that's
                # what the env-default URL capture handles separately.
                if url_node.values and isinstance(url_node.values[0], ast.Constant):
                    prefix = url_node.values[0].value
                    if isinstance(prefix, str):
                        for h in _hosts_from_string(prefix):
                            self.r.hosts.add(h)
            note_bits = []
            if url_kind == "fstring":
                note_bits.append("url is f-string")
            elif url_kind == "concat":
                note_bits.append("url is string concat")
            elif url_kind == "name":
                note_bits.append("url is a variable")
            if tls_off:
                note_bits.append("verify=False")
                self.r.tls_disabled_calls.append(self._site(node, name, "verify=False"))
            self.r.http_calls.append(self._site(node, name, "; ".join(note_bits)))
            if url_kind in ("fstring", "concat"):
                # Flag for URL-safety review
                self.r.url_construction_warnings.append(
                    self._site(node, name, f"url constructed via {url_kind}")
                )

        # File system writes
        elif name in _FS_WRITE_FUNCS or self._is_path_write(name):
            self.r.fs_write_calls.append(self._site(node, name))

        # File system reads
        elif name in _FS_READ_FUNCS:
            self.r.fs_read_calls.append(self._site(node, name))

        # open() with mode awareness
        elif bare == "open" and "." not in name:
            mode = "r"  # default
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            else:
                mode_kw = _get_kwarg_value(node, "mode")
                if isinstance(mode_kw, ast.Constant):
                    mode = str(mode_kw.value)
            note = f"mode={mode!r}"
            site = self._site(node, "open", note)
            self.r.open_calls.append(site)
            if any(c in mode for c in ("w", "a", "x", "+")):
                self.r.fs_write_calls.append(site)
            else:
                self.r.fs_read_calls.append(site)

        # Env var reads
        elif name in _ENV_READ_FUNCS or name == "os.environ.__getitem__":
            var_name = self._first_string_arg(node) or "<unknown>"
            self.r.env_reads.setdefault(var_name, []).append(self._site(node, name))
            # Capture URL-shaped DEFAULT values, e.g. `os.environ.get("API",
            # "https://example.com")`. These resolve to the URL when the env
            # var isn't set — i.e., they ARE a host the package can contact
            # under default config. Without this, an MCP that uses the
            # standard "env-var-with-default-URL" pattern looked to the
            # scanner like an unknown-destination call, which spuriously
            # deducted score points. Flow analysis through the bound
            # variable is out of scope; capturing the literal default at
            # the call site is good enough.
            if name in ("os.environ.get", "os.getenv") and len(node.args) >= 2:
                default = _string_constant(node.args[1])
                if default:
                    for h in _hosts_from_string(default):
                        self.r.hosts.add(h)

        # Stdio
        elif name in _STDIN_FUNCS or bare == "input":
            self.r.stdin_calls.append(self._site(node, name))
        elif name in _STDOUT_FUNCS:
            self.r.stdout_calls.append(self._site(node, name))
        elif name in _STDERR_FUNCS:
            self.r.stderr_calls.append(self._site(node, name))

        # Inbound network — server constructors / bind / .run() patterns
        elif name in _INBOUND_FUNCS or bare in ("bind",) and self._looks_like_socket_bind(node):
            self.r.inbound_calls.append(self._site(node, name or bare))

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # os.environ["FOO"] — a Subscript, not a Call
        if isinstance(node.value, ast.Attribute):
            full = _dotted_name(node.value)
            if full == "os.environ":
                key = self._subscript_key(node)
                if key is not None:
                    self.r.env_reads.setdefault(key, []).append(self._site(node, "os.environ[]"))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        # Dimension 9 — string-content safety. Scan every string literal
        # ≥ _MIN_STR_LEN for zero-width unicode + injection patterns.
        if isinstance(node.value, str) and len(node.value) >= _MIN_STR_LEN:
            s = node.value
            # Zero-width / directional-override unicode
            if any(ch in s for ch in _ZERO_WIDTH_CHARS):
                # Note which categories of zero-width chars were found —
                # bidi-overrides are particularly suspicious vs. mere
                # zero-width-spaces.
                bidi = any(ch in s for ch in "‪‫‬‭‮")
                kind = "bidi-override" if bidi else "zero-width"
                self.r.zero_width_strings.append(
                    self._site(node, "<string-literal>", note=f"{kind} chars detected")
                )
            # Injection patterns
            for pat in _INJECTION_PATTERNS:
                m = pat.search(s)
                if m:
                    snippet = s[max(0, m.start() - 10):m.end() + 10].replace("\n", " ")
                    self.r.injection_pattern_strings.append(
                        self._site(node, "<string-literal>", note=f"matched: …{snippet}…")
                    )
                    break  # one match per string is enough
        self.generic_visit(node)

    @staticmethod
    def _subscript_key(node: ast.Subscript) -> str | None:
        sl = node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            return sl.value
        return None

    @staticmethod
    def _first_string_arg(call: ast.Call) -> str | None:
        if call.args:
            return _string_constant(call.args[0])
        return None

    @staticmethod
    def _is_http_client_call(name: str) -> bool:
        # Exact match against the catalog
        if name in _HTTP_CLIENT_FUNCS:
            return True
        # Naming-heuristic for instance methods: `session.get(...)` resolves
        # to name "session.get". Treat as HTTP only if the final attr is an
        # HTTP verb AND the receiver name looks plausibly like an HTTP
        # client (contains "session", "client", "http", or matches a known
        # http module). Otherwise we'd false-positive on completely unrelated
        # calls like os.environ.get, dict.get, queue.get, defaultdict.get,
        # etc. (Caught 2026-05-10 — the v0.1.0 heuristic flagged
        # os.environ.get as an HTTP call, dropping all env-read detection.)
        if "." in name:
            verbs = {"get", "post", "put", "delete", "head", "patch", "request"}
            tail = name.rsplit(".", 1)[-1]
            if tail not in verbs:
                return False
            receiver_chain = name.rsplit(".", 1)[0].lower()
            http_signals = ("session", "client", "http", "requests", "httpx", "urllib", "aiohttp")
            return any(sig in receiver_chain for sig in http_signals)
        return False

    @staticmethod
    def _is_path_write(name: str) -> bool:
        # `Path(...).write_text` / `pathlib.Path(...).write_bytes` resolve to
        # `Path.write_text` etc. via _dotted_name. Already covered in
        # _FS_WRITE_FUNCS as suffix-tail entries; this is just a hook for
        # additional Path-variant patterns we add later.
        return False

    @staticmethod
    def _looks_like_socket_bind(node: ast.Call) -> bool:
        # `s.bind((host, port))` — single tuple arg
        if len(node.args) == 1 and isinstance(node.args[0], ast.Tuple):
            return True
        return False


# ── Dependency parsing ──────────────────────────────────────────────────────

def _parse_deps(target: Path) -> tuple[list[str], str]:
    """Return (deps_list, source_filename)."""
    pp = target / "pyproject.toml"
    req = target / "requirements.txt"
    if pp.exists():
        try:
            if sys.version_info >= (3, 11):
                import tomllib
                with pp.open("rb") as f:
                    data = tomllib.load(f)
            else:
                # Python 3.10 fallback — read as text + minimal parse for deps
                # (tomllib is 3.11+; we don't want to add tomli as a dep, so
                # for 3.10 we skip detailed parsing and report "needs 3.11")
                return [], "pyproject.toml (3.11+ required for full parse)"
            deps = list(data.get("project", {}).get("dependencies", []))
            return deps, "pyproject.toml"
        except Exception as e:
            return [], f"pyproject.toml (parse error: {e})"
    if req.exists():
        try:
            lines = req.read_text().splitlines()
            deps = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]
            return deps, "requirements.txt"
        except Exception as e:
            return [], f"requirements.txt (read error: {e})"
    return [], "(none)"


# ── Public API ──────────────────────────────────────────────────────────────

def scan(target_path: str | Path) -> ScanResult:
    """Walk every .py file under target_path. Returns a ScanResult."""
    target = Path(target_path).resolve()
    result = ScanResult(target_path=str(target))

    if target.is_file() and target.suffix == ".py":
        py_files = [target]
    elif target.is_dir():
        py_files = sorted(p for p in target.rglob("*.py") if "__pycache__" not in p.parts)
    else:
        raise ValueError(f"target_path must be a .py file or directory: {target}")

    for py in py_files:
        try:
            src = py.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        result.files_scanned += 1
        result.lines_scanned += src.count("\n") + 1
        try:
            tree = ast.parse(src, filename=str(py))
        except SyntaxError:
            continue
        rel = str(py.relative_to(target)) if target.is_dir() else py.name
        scanner = _Scanner(result, rel)
        scanner.visit(tree)

    deps, dep_src = _parse_deps(target if target.is_dir() else target.parent)
    result.dependencies = deps
    result.dep_source = dep_src

    return result


def scan_to_json(target_path: str | Path) -> str:
    """Convenience: scan + dump as JSON."""
    r = scan(target_path)
    payload = {
        "target_path": r.target_path,
        "files_scanned": r.files_scanned,
        "lines_scanned": r.lines_scanned,
        "http_calls": [_call_dict(c) for c in r.http_calls],
        "hosts": sorted(r.hosts),
        "tls_disabled_calls": [_call_dict(c) for c in r.tls_disabled_calls],
        "subprocess_calls": [_call_dict(c) for c in r.subprocess_calls],
        "dynamic_exec_calls": [_call_dict(c) for c in r.dynamic_exec_calls],
        "fs_write_calls": [_call_dict(c) for c in r.fs_write_calls],
        "fs_read_calls": [_call_dict(c) for c in r.fs_read_calls],
        "env_reads": {k: [_call_dict(c) for c in v] for k, v in r.env_reads.items()},
        "stdin_calls": [_call_dict(c) for c in r.stdin_calls],
        "stdout_calls": [_call_dict(c) for c in r.stdout_calls],
        "stderr_calls": [_call_dict(c) for c in r.stderr_calls],
        "inbound_calls": [_call_dict(c) for c in r.inbound_calls],
        "url_construction_warnings": [_call_dict(c) for c in r.url_construction_warnings],
        "dependencies": r.dependencies,
        "dep_source": r.dep_source,
        "zero_width_strings": [_call_dict(c) for c in r.zero_width_strings],
        "injection_pattern_strings": [_call_dict(c) for c in r.injection_pattern_strings],
    }
    return json.dumps(payload, indent=2)


def _call_dict(c: CallSite) -> dict:
    return {"file": c.file, "line": c.line, "name": c.name, "note": c.note}
