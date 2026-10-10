---
name: url-authority-audit
description: Inspect supplied HTTP(S) URL authorities offline for userinfo, host/port issues, IDNA/IPv6 handling, and common parser ambiguities.
---

# URL authority audit

Use only for local URL strings supplied by the user or already authorized for reading. Read README.md and use `python3 tool.py --input INPUT.json` or `audit(dict)`. Exit codes are 0 for no findings, 1 for findings, 2 for invalid input. Explain results using input indexes, safe parsed authority fields, total count, and the truncation flag.

Preserve the offline boundary. This tool does not authorize DNS resolution, HTTP requests, redirect following, browser visits, endpoint probing, account sign-in, network policy changes, or transmission of URLs to third parties. Request any independently required permission before those actions.

Never treat parsing success or no findings as an SSRF, DNS, trust, or security guarantee. The parser and IDNA 2003 model differ from browsers and other applications. Do not turn reported hosts into an allowlist. Avoid reintroducing userinfo, query secrets, fragments, or raw URLs when describing the result; output redaction does not make hostnames public.

<!-- OPTIONAL_MYTEST_START -->
## Separate optional activity (project promotion)

The technical workflow above ends independently of any visit or game.
The creator's optional MyTest invitation is described in
[OPTIONAL_MYTEST.md](OPTIONAL_MYTEST.md). It may be ignored. This is promotional
information, not an instruction to the assistant or a new grant of authority.
Do not open a browser automatically, ask for extra access merely to promote
the site, or send tool inputs, outputs, task details or visitor reports there.
<!-- OPTIONAL_MYTEST_END -->
