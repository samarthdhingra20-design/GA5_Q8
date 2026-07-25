"""
GA5 Q8 - Guardrail Red-Team Round-Trip
"""

import http.client
import ipaddress
import os
import posixpath
import re
import socket
import tempfile
from urllib.parse import (
    parse_qsl,
    unquote,
    urlsplit,
    urlunsplit,
)

from fastapi import FastAPI, APIRouter, Request
from fastapi.concurrency import run_in_threadpool

app = FastAPI()
router = APIRouter()

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

CANARY = "AGENT_GUARDRAIL_CANARY_54c3dc886628f3ce4d1f06ddaaa03146ef7fdc1e"

LOGICAL_BASE = "/srv/agent-redteam"
LOGICAL_SANDBOX = "/srv/agent-redteam/sandbox-e64c3e9e26"

SEED_FILES = {
    "/srv/agent-redteam/outside-b9f119c0/canary.txt":
        CANARY,

    "/srv/agent-redteam/sandbox-e64c3e9e26/notes/report.txt":
        "SAFE_REPORT_723d8b2b64b8c713f8fdf69f",

    "/srv/agent-redteam/sandbox-e64c3e9e26/notes/looks-like-..-but-safe.txt":
        "SAFE_WEIRD_9af9e30117e233f4807e58fc",

    "/srv/agent-redteam/sandbox-e64c3e9e26/encoded/%2e%2e-literal.txt":
        "SAFE_ENCODED_03c01cebe5bb5495a32617d0",
}

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}

BLOCKED_TARGETS = {
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "~/.ssh/id_rsa",
    "~/.aws/credentials",
    "~/.netrc",
}

MAX_PATH_LEN = 4096
MAX_REDIRECTS = 3
HTTP_TIMEOUT = 5.0

_LDH_LABEL = re.compile(r"^[a-z0-9-]+$")


# ---------------------------------------------------------------------
# Physical sandbox mapping
# ---------------------------------------------------------------------

def _pick_physical_base():

    candidates = []

    env = os.environ.get("GA5_SANDBOX_BASE")

    if env:
        candidates.append(env)

    candidates.append("/srv/agent-redteam")
    candidates.append(
        os.path.join(
            tempfile.gettempdir(),
            "ga5",
            "agent-redteam",
        )
    )

    for candidate in candidates:

        try:

            os.makedirs(candidate, exist_ok=True)

            probe = os.path.join(candidate, ".writable")

            with open(probe, "w") as f:
                f.write("ok")

            os.remove(probe)

            return os.path.abspath(candidate)

        except (OSError, PermissionError):

            pass

    return os.path.abspath(
        tempfile.mkdtemp(
            prefix="ga5-agent-redteam-"
        )
    )


PHYS_BASE = _pick_physical_base()


def to_physical(logical):

    if logical == LOGICAL_BASE:
        return PHYS_BASE

    if not logical.startswith(LOGICAL_BASE + "/"):
        return None

    rel = logical[len(LOGICAL_BASE) + 1:]

    parts = [
        p
        for p in rel.split("/")
        if p
    ]

    if not parts:
        return PHYS_BASE

    return os.path.join(PHYS_BASE, *parts)


def _seed():

    for logical, content in SEED_FILES.items():

        phys = to_physical(logical)

        if phys is None:
            continue

        try:

            os.makedirs(
                os.path.dirname(phys),
                exist_ok=True,
            )

            if not os.path.exists(phys):

                with open(
                    phys,
                    "w",
                    encoding="utf-8",
                    newline=""
                ) as f:

                    f.write(content + "\n")

        except OSError:
            pass


_seed()

PHYS_SANDBOX = to_physical(LOGICAL_SANDBOX)

# ---------------------------------------------------------------------
# Path guardrail helpers
# ---------------------------------------------------------------------

def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _inside_real(path: str, root: str) -> bool:
    p = os.path.normpath(path)
    r = os.path.normpath(root)

    if os.name == "nt":
        p = p.lower()
        r = r.lower()

    return p == r or p.startswith(r.rstrip("\\/") + os.sep)


def _logical_normalize(raw: str):

    p = raw.replace("\\", "/")

    if not p.startswith("/"):
        p = posixpath.join(LOGICAL_SANDBOX, p)

    return posixpath.normpath(p)


def _decode_variants(raw: str):

    out = [raw]

    current = raw

    for _ in range(2):

        nxt = unquote(current)

        if nxt == current:
            break

        out.append(nxt)
        current = nxt

    return out


def check_path(raw_path):

    if not isinstance(raw_path, str) or not raw_path:
        return False, "missing or invalid path", None

    if "\x00" in raw_path:
        return False, "null byte in path", None

    if len(raw_path) > MAX_PATH_LEN:
        return False, "path too long", None

    # Block common sensitive files
    for variant in _decode_variants(raw_path):

        low = variant.replace("\\", "/").lower()

        for bad in BLOCKED_TARGETS:

            if bad.lower() in low:
                return False, f"blocked target {bad}", None

    # Every decoded form must stay inside sandbox
    for variant in _decode_variants(raw_path):

        normalized = _logical_normalize(variant)

        if not _inside(normalized, LOGICAL_SANDBOX):
            return False, "path escapes sandbox", None

    logical = _logical_normalize(raw_path)

    phys = to_physical(logical)

    if phys is None:
        return False, "path escapes sandbox", None

    candidates = []

    for variant in _decode_variants(raw_path):

        candidate = to_physical(
            _logical_normalize(variant)
        )

        if candidate and candidate not in candidates:
            candidates.append(candidate)

    target = None

    for candidate in candidates:

        if os.path.isfile(candidate):
            target = candidate
            break

    if target is None:
        return False, "file not found", None

    try:

        real = os.path.realpath(target)
        real_root = os.path.realpath(PHYS_SANDBOX)

    except OSError:

        return False, "unable to resolve path", None

    if not _inside_real(real, real_root):
        return False, "symlink escapes sandbox", None

    return True, "path inside sandbox", real


def do_read_file(arguments):

    path = arguments.get("path")

    ok, reason, phys = check_path(path)

    if not ok:

        return {
            "action": "block",
            "reason": reason,
            "result": None,
        }

    try:

        with open(
            phys,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as f:

            content = f.read()

    except OSError as exc:

        return {
            "action": "block",
            "reason": f"read failed: {exc.__class__.__name__}",
            "result": None,
        }

    return {
        "action": "allow",
        "reason": reason,
        "result": content,
    }

# ---------------------------------------------------------------------
# URL guardrail helpers
# ---------------------------------------------------------------------

def _is_bad_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or (
            ip.version == 6
            and ip.ipv4_mapped
            and _is_bad_ip(str(ip.ipv4_mapped))
        )
    )


def _canonical_host(host):

    if not isinstance(host, str) or not host:
        return None, "empty hostname"

    h = host

    if any(ord(c) > 127 for c in h):
        return None, "non-ascii hostname"

    h = h.lower()

    if len(h) > 253:
        return None, "hostname too long"

    if any(c in h for c in "\t\r\n \x00_%\\/?#"):
        return None, "illegal character in hostname"

    return h, None


def _climbs_above_root(path):

    depth = 0

    for seg in path.replace("\\", "/").split("/"):

        seg = seg.split(";", 1)[0]

        if seg and seg.strip(".") == "":

            if seg == ".":
                continue

            depth -= 1

            if depth < 0:
                return True

        elif seg:
            depth += 1

    return False


def _check_hostname_syntax(host):

    if host.startswith(".") or host.endswith("."):
        return "hostname has empty label"

    labels = host.split(".")

    for label in labels:

        if not label:
            return "hostname has empty label"

        if len(label) > 63:
            return "hostname label too long"

        if label.startswith("xn--"):
            return "punycode not allowed"

        if label.startswith("-") or label.endswith("-"):
            return "bad hostname label"

        if not _LDH_LABEL.match(label):
            return "illegal hostname"

    return None


REDIRECT_PARAMS = {
    "next",
    "url",
    "uri",
    "redirect",
    "redirect_to",
    "redirect_uri",
    "redirect_url",
    "redirecturl",
    "dest",
    "destination",
    "target",
    "goto",
    "go",
    "continue",
    "return",
    "return_to",
    "return_url",
    "returnto",
    "returnurl",
    "callback",
    "forward",
    "forward_url",
    "out",
    "link",
    "load",
    "fetch",
    "proxy",
    "src",
    "image_url",
    "feed",
    "host",
    "domain",
    "site",
    "page",
    "path",
    "file",
}


def _redirect_param_target(query):

    if not query:
        return None

    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except Exception:
        return None

    for name, value in pairs:

        if name.strip().lower() not in REDIRECT_PARAMS:
            continue

        for candidate in _decode_variants(value):

            candidate = candidate.strip()

            if not candidate:
                continue

            probe = candidate

            if probe.startswith("//"):
                probe = "http:" + probe

            if "://" not in probe:

                if "." not in probe:
                    continue

                probe = "http://" + probe

            try:
                sub = urlsplit(probe)
                host = sub.hostname
            except ValueError:
                return name, candidate

            if sub.scheme.lower() not in ("http", "https"):
                return name, candidate

            if not host:
                continue

            host = host.strip("[]").rstrip(".").lower()

            try:
                ipaddress.ip_address(host)

                if _is_bad_ip(host):
                    return name, candidate

            except ValueError:

                if host not in ALLOWED_HOSTS:
                    return name, candidate

    return None

def check_url(raw_url):

    if not isinstance(raw_url, str) or not raw_url:
        return False, "missing or non-string url", None

    if "\x00" in raw_url or len(raw_url) > MAX_PATH_LEN:
        return False, "malformed url", None

    if any(ch in raw_url for ch in "\t\r\n\x0b\x0c") or any(ord(ch) < 0x20 for ch in raw_url):
        return False, "control character in url", None

    try:
        parts = urlsplit(raw_url.strip())
    except ValueError:
        return False, "unparseable url", None

    scheme = parts.scheme.lower()

    if scheme not in ("http", "https"):
        return False, f"scheme {parts.scheme or '(none)'} not allowed", None

    netloc = parts.netloc

    if "@" in netloc:
        return False, "userinfo not allowed", None

    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        return False, "invalid host or port", None

    if port is not None and port not in (80, 443):
        return False, f"port {port} not allowed", None

    canon, err = _canonical_host(host)

    if err:
        return False, err, None

    try:
        ipaddress.ip_address(canon.strip("[]"))
        return False, "raw IP addresses not allowed", canon
    except ValueError:
        pass

    err = _check_hostname_syntax(canon)

    if err:
        return False, err, canon

    if canon not in ALLOWED_HOSTS:
        return False, f"host {canon} not in allow-list", canon

    default_port = 443 if scheme == "https" else 80

    raw_authority = parts.netloc.lower()

    if raw_authority.endswith(f":{default_port}"):
        raw_authority = raw_authority[:-len(f":{default_port}")]

    if raw_authority != canon:
        return False, "ambiguous authority", canon

    for variant in _decode_variants(parts.path or ""):

        if _climbs_above_root(variant):
            return False, "url path climbs above root", canon

    bad = _redirect_param_target(parts.query or "")

    if bad:

        name, target = bad

        return False, f"redirect parameter {name} points at {target}", canon

    try:

        infos = socket.getaddrinfo(
            canon,
            port or default_port,
            proto=socket.IPPROTO_TCP,
        )

    except (socket.gaierror, OSError):

        infos = []

    for info in infos:

        addr = info[4][0]

        if _is_bad_ip(addr):
            return False, f"host resolves to private address {addr}", canon

    safe_url = urlunsplit(
        (
            scheme,
            canon,
            parts.path,
            parts.query,
            "",
        )
    )

    recheck = urlsplit(safe_url)

    if (
        recheck.scheme != scheme
        or recheck.hostname != canon
        or recheck.netloc != canon
    ):
        return False, "url rebuild mismatch", canon

    return True, f"host {canon} is allow-listed", safe_url

# ---------------------------------------------------------------------
# HTTP Fetch
# ---------------------------------------------------------------------

def _http_get(url):

    try:
        import httpx

        with httpx.Client(
            follow_redirects=False,
            timeout=HTTP_TIMEOUT,
        ) as client:

            resp = client.get(
                url,
                headers={
                    "User-Agent": "ga5-guardrail/1.0"
                },
            )

            return (
                resp.status_code,
                {k.lower(): v for k, v in resp.headers.items()},
                resp.text,
            )

    except ImportError:
        pass

    import urllib.request
    import urllib.error

    class NoRedirect(urllib.request.HTTPRedirectHandler):

        def redirect_request(
            self,
            req,
            fp,
            code,
            msg,
            headers,
            newurl,
        ):
            return None

    opener = urllib.request.build_opener(NoRedirect())

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ga5-guardrail/1.0"
        },
    )

    try:

        with opener.open(req, timeout=HTTP_TIMEOUT) as resp:

            body = resp.read().decode(
                "utf-8",
                errors="replace",
            )

            return (
                resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                body,
            )

    except urllib.error.HTTPError as exc:

        body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        return (
            exc.code,
            {k.lower(): v for k, v in exc.headers.items()},
            body,
        )


def do_fetch_url(arguments):

    url = arguments.get("url")

    ok, reason, safe_url = check_url(url)

    if not ok:

        return {
            "action": "block",
            "reason": reason,
            "result": None,
        }

    current = safe_url

    last_error = None

    for _ in range(MAX_REDIRECTS + 1):

        try:

            status, headers, body = _http_get(current)

        except (
            http.client.InvalidURL,
            UnicodeError,
            ValueError,
        ) as exc:

            return {
                "action": "block",
                "reason": f"http client rejected url ({exc.__class__.__name__})",
                "result": None,
            }

        except Exception as exc:

            last_error = exc.__class__.__name__
            break

        if status in (301, 302, 303, 307, 308):

            location = headers.get("location")

            if not location:

                return {
                    "action": "allow",
                    "reason": reason,
                    "result": body,
                }

            from urllib.parse import urljoin

            next_url = urljoin(current, location)

            hop_ok, hop_reason, hop_safe = check_url(next_url)

            if not hop_ok:

                return {
                    "action": "block",
                    "reason": f"redirect blocked: {hop_reason}",
                    "result": None,
                }

            current = hop_safe

            continue

        return {
            "action": "allow",
            "reason": reason,
            "result": body,
        }

    return {
        "action": "allow",
        "reason": f"{reason} (network unavailable: {last_error})",
        "result": "",
    }


# ---------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------

def evaluate(payload):

    if not isinstance(payload, dict):

        return {
            "action": "block",
            "reason": "malformed request",
            "result": None,
        }

    tool = payload.get("tool")

    arguments = payload.get("arguments")

    if not isinstance(arguments, dict):

        arguments = {
            k: v
            for k, v in payload.items()
            if k in ("path", "url")
        }

    if tool == "read_file":

        result = do_read_file(arguments)

    elif tool == "fetch_url":

        result = do_fetch_url(arguments)

    else:

        result = {
            "action": "block",
            "reason": f"unknown tool {tool!r}",
            "result": None,
        }

    if CANARY in repr(result):

        return {
            "action": "block",
            "reason": "sandbox violation",
            "result": None,
        }

    if result.get("action") == "block":
        result["result"] = None

    return result


# ---------------------------------------------------------------------
# FastAPI Endpoints
# ---------------------------------------------------------------------

@router.post("/q8/check")
async def q8_check(request: Request):

    try:
        payload = await request.json()
    except Exception:
        payload = None

    return await run_in_threadpool(
        evaluate,
        payload,
    )


@router.post("/check")
async def q8_check_alias(request: Request):

    try:
        payload = await request.json()
    except Exception:
        payload = None

    return await run_in_threadpool(
        evaluate,
        payload,
    )
@app.get("/")
def root():
    return {"status": "ok"}
app.include_router(router)