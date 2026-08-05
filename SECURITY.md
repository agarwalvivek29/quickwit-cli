# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** via GitHub's
["Report a vulnerability"](https://github.com/agarwalvivek29/quickwit-cli/security/advisories/new)
flow, or by emailing the maintainer. Do not open a public issue.

We aim to acknowledge reports within 3 business days.

## Scope notes

- `qwproxy` is an **authentication and audit boundary**. Findings that allow bypassing JWT validation,
  the read-only path allowlist, or that leak response bodies into the audit store are in scope and
  treated as high severity.
- The audit store intentionally records the **request** (including the search query) but **never the
  response body**. A change that causes response payloads to be persisted is a security bug.
