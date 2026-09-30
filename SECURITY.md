# Security Policy

## Project Status

This is an **experimental academic prototype** developed for Smart India Hackathon 2026
(Problem Statement SIH26163, NTRO). It is **not a production security tool**.

It has not undergone independent third-party security audit. Do not rely on it to provide
security assurances in any real or production environment.

---

## Authorized Use Only

This platform is designed **exclusively for authorized defensive security assessment**
of the World Monitor application in controlled localhost environments.

**You must have explicit written authorization** before running any assessment probes
against any target, including self-hosted instances.

Unauthorized use of this tool against systems you do not own or have written permission
to test may violate applicable laws including (but not limited to) the Indian Information
Technology Act, 2000 and international equivalents.

---

## Localhost-Only Default Scope

The Scope Guard (`engine/scope_guard.py`) enforces a **fail-closed localhost boundary**:

- Only `localhost`, `127.0.0.1`, and `::1` are permitted as probe targets.
- Any probe targeting a public IP address or external domain is blocked before the
  request leaves the host.
- This restriction cannot be overridden via API parameters or environment variables.

---

## Intentionally Vulnerable Lab Warning

The `lab/` directory contains a **deliberately insecure** synthetic application:

- It is seeded with **entirely fictional/synthetic data** — no real credentials,
  no real PII, no real classified information.
- It exposes known vulnerability patterns for demonstration purposes.
- **Do not expose the lab to any network interface other than 127.0.0.1.**
- **Do not seed it with real data.**
- Do not use the lab's default credentials (admin/analyst/viewer) on any real system.

---

## Secret Management

- Never commit a real `.env` file. Only `.env.example` (with placeholder values) is
  tracked in version control.
- Generate a strong, random `JWT_SECRET_KEY` (minimum 32 characters) for local use:
  ```bash
  # Linux/macOS
  python -c "import secrets; print(secrets.token_hex(32))"
  # Or using openssl
  openssl rand -hex 32
  ```
- Rotate secrets immediately if accidental exposure is suspected.
- Do not use the example OPERATOR_ID (`sec_lead_auditor`) in multi-user environments;
  assign a unique identifier per operator.

---

## No Real Sensitive / Production Data

- Do not store real credentials, PII, or classified information in any database
  managed by this platform.
- The `engine/assessment.db` and `lab/lab.db` files are **generated locally at runtime**
  and are excluded from version control via `.gitignore`.
- Generated PDF reports may contain findings and evidence captured from the lab.
  Keep these reports local and protected if they include sensitive probe details.

---

## Reporting a Vulnerability in This Project

This is a hackathon prototype. If you discover a security issue in the platform code itself
(not a finding in the synthetic lab):

1. **Do not open a public GitHub issue** with exploit details.
2. Contact the project maintainer privately:
   - Describe the vulnerability and steps to reproduce.
   - Allow reasonable time for review before any public disclosure.
3. We will acknowledge receipt and coordinate a fix or disclosure timeline.

We appreciate responsible disclosure. We cannot offer bug bounties or enterprise SLAs
for this academic project.

---

## Disclaimer

> THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
> THE AUTHORS MAKE NO REPRESENTATIONS REGARDING ITS FITNESS FOR ANY PARTICULAR PURPOSE.
> USE ENTIRELY AT YOUR OWN RISK. SEE LICENSE FOR FULL TERMS.
