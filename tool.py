#!/usr/bin/env python3
"""Offline audit, Python 3.12+ standard library only. Never performs networking."""
import argparse
import json
import stat
import sys
from pathlib import Path

MAX_BYTES = 1024 * 1024
MAX_ITEMS = 256
MAX_FINDINGS = 500

class InputError(ValueError):
    """Safe error containing only a fixed code, never supplied data."""

class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid_arguments")

def object_schema(value, allowed, required):
    if not isinstance(value, dict) or set(value) - allowed or not required <= set(value):
        raise InputError("invalid_schema")

def integer(value, low, high):
    return type(value) is int and low <= value <= high

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate_json_member")
        result[key] = value
    return result

def reject_constant(value):
    raise InputError("non_finite_json_number")

class Report:
    def __init__(self):
        self.findings, self.count = [], 0
    def add(self, code, **location):
        self.count += 1
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(dict(code=code, **location))
    def finish(self, **data):
        return {"tool": TOOL, "status": "fail" if self.count else "pass",
                "finding_count": self.count, "findings": self.findings,
                "findings_truncated": self.count > len(self.findings), **data}

def error_result(code):
    return {"tool": TOOL, "status": "error", "error": code}

def audit(data):
    """Audit a JSON-shaped dict; return deterministic JSON-compatible data."""
    try:
        return _audit(data)
    except InputError as exc:
        return error_result(str(exc))

def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--input", default="-", help="JSON file, or - for stdin (default)")
        args = parser.parse_args(argv)
        if args.input == "-":
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            path = Path(args.input)
            if not stat.S_ISREG(path.stat().st_mode):
                raise InputError("regular_file_required")
            with path.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InputError("input_size_limit")
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                              parse_constant=reject_constant)
        except (ValueError, RecursionError) as exc:
            if isinstance(exc, InputError):
                raise
            raise InputError("invalid_json") from None
        result = audit(data)
    except InputError as exc:
        result = error_result(str(exc))
    except (OSError, UnicodeError):
        result = error_result("unreadable_utf8_input")
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, indent=2, allow_nan=False))
    return {"pass": 0, "fail": 1, "error": 2}[result["status"]]

import ipaddress
import re
from urllib.parse import urlsplit

TOOL = "url-authority-audit"
MAX_URL = 8192
DEFAULT_PORTS = {"http": 80, "https": 443}

def inspect_url(value, index, report):
    """Return only safe authority fields; do not return supplied URL components."""
    item = {"index": index, "parsed": False}
    def add(code):
        report.add(code, index=index)
    if any(ord(ch) <= 32 or ord(ch) == 127 or ch.isspace() for ch in value):
        add("whitespace_or_control")
    if "\\" in value:
        add("backslash_ambiguity")
    try:
        parts = urlsplit(value)
    except ValueError:
        add("url_parse_error")
        return item
    scheme = parts.scheme.lower()
    item.update(scheme=scheme if scheme in DEFAULT_PORTS else None, query_present="?" in value.split("#", 1)[0],
                fragment_present="#" in value,
                userinfo_present="@" in parts.netloc)
    if scheme not in DEFAULT_PORTS:
        add("unsupported_or_missing_scheme")
    if not parts.netloc:
        add("missing_authority")
        return item
    if "@" in parts.netloc:
        add("userinfo_present")
    if parts.netloc.count("@") > 1:
        add("multiple_at_ambiguity")
    authority = parts.netloc.rsplit("@", 1)[-1]
    if "%" in authority:
        add("percent_encoded_or_scoped_authority")
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        add("invalid_host_or_port")
        return item
    if not host:
        add("missing_host")
        return item
    # Everything emitted below is rebuilt from validated ASCII host/port data.
    if host.endswith("."):
        add("trailing_dot_host")
    if any(ord(ch) > 127 for ch in host):
        add("unicode_idna_mapping")
    host_ascii, kind = None, None
    if authority.startswith("["):
        close = authority.find("]")
        suffix = authority[close + 1:]
        if close < 0 or (suffix and not suffix.startswith(":")):
            add("bracket_suffix_ambiguity")
            return item
        if "%" in host:
            add("ipv6_zone_not_supported")
            return item
        try:
            address = ipaddress.IPv6Address(host)
            host_ascii, kind = str(address), "ipv6"
        except ValueError:
            add("unsupported_ip_literal")
            return item
        port_text = suffix[1:] if suffix.startswith(":") else None
    else:
        if ":" in host or "[" in authority or "]" in authority:
            add("unbracketed_or_invalid_ip_literal")
            return item
        port_text = authority.rsplit(":", 1)[1] if ":" in authority else None
        try:
            address = ipaddress.IPv4Address(host)
            host_ascii, kind = str(address), "ipv4"
        except ValueError:
            try:
                candidate = host.encode("idna").decode("ascii").lower()
                bare = candidate[:-1] if candidate.endswith(".") else candidate
                labels = bare.split(".")
                if not 1 <= len(bare) <= 253 or any(
                    not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in labels
                ):
                    raise ValueError
                for label in labels:
                    if label.startswith("xn--"):
                        if label.encode("ascii").decode("idna").encode("idna").decode("ascii") != label:
                            raise ValueError
                host_ascii, kind = candidate, "dns_name"
                if re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]*)", labels[-1]):
                    add("numeric_host_ambiguity")
            except (UnicodeError, ValueError):
                add("invalid_dns_or_idna_host")
                return item
    if port_text == "":
        add("empty_port")
    if port_text and (not port_text.isascii() or not port_text.isdecimal()):
        add("invalid_host_or_port")
        return item
    if port_text and len(port_text) > 1 and port_text.startswith("0"):
        add("noncanonical_port")
    if port == 0:
        add("zero_port")
    effective = port if port is not None else DEFAULT_PORTS.get(scheme)
    item.update(parsed=True, host=host_ascii, host_kind=kind,
                explicit_port=port, effective_port=effective)
    if scheme in DEFAULT_PORTS:
        display = "[" + host_ascii + "]" if kind == "ipv6" else host_ascii
        item["origin"] = scheme + "://" + display + ":" + str(effective)
    return item

def _audit(data):
    object_schema(data, {"urls"}, {"urls"})
    values = data["urls"]
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_ITEMS:
        raise InputError("urls_count_limit")
    if any(not isinstance(value, str) or not 1 <= len(value) <= MAX_URL for value in values):
        raise InputError("invalid_url_entry")
    if sum(len(value) for value in values) > MAX_BYTES:
        raise InputError("url_content_limit")
    report = Report()
    items = [inspect_url(value, index, report) for index, value in enumerate(values)]
    return report.finish(url_count=len(values), urls=items, parser_model="urllib.parse+stdlib-idna2003")

if __name__ == "__main__":
    raise SystemExit(main())
