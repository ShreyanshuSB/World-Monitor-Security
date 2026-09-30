# Third-Party Notices

This document lists third-party components used by the World Monitor Security
Assessment Platform (SIH26163 / NTRO). All licenses were verified from the
official package metadata at the time of writing.

---

## 1. Original Project Code

The following directories contain original source code licensed under MIT
(see LICENSE):

- `api/`, `engine/`, `lab/`, `reports/`, `tests/`, `dashboard/src/`
- `run.sh`, `run.bat`

---

## 2. Python Dependencies

Declared in `requirements.txt`. Install via `pip install -r requirements.txt`.

| Package | License | Homepage |
|---------|---------|---------|
| FastAPI | MIT | https://fastapi.tiangolo.com |
| Uvicorn | BSD-3-Clause | https://www.uvicorn.org |
| HTTPX | BSD-3-Clause | https://www.python-httpx.org |
| SQLAlchemy | MIT | https://www.sqlalchemy.org |
| Pydantic | MIT | https://docs.pydantic.dev |
| ReportLab | BSD-style (ReportLab License) | https://www.reportlab.com/opensource/ |
| pytest | MIT | https://docs.pytest.org |
| pytest-asyncio | Apache-2.0 | https://github.com/pytest-dev/pytest-asyncio |

> ReportLab is distributed under the ReportLab Open Source License, which is
> BSD-compatible. See https://www.reportlab.com/dev/opensource/rl-license/ for
> exact terms.

---

## 3. Frontend (npm) Dependencies

Declared in `dashboard/package.json`.

### Runtime dependencies

| Package | License | Homepage |
|---------|---------|---------|
| react | MIT | https://react.dev |
| react-dom | MIT | https://react.dev |
| recharts | MIT | https://recharts.org |
| lucide-react | ISC | https://lucide.dev |
| tailwindcss | MIT | https://tailwindcss.com |
| clsx | MIT | https://github.com/lukeed/clsx |
| postcss | MIT | https://postcss.org |
| autoprefixer | MIT | https://github.com/postcss/autoprefixer |
| @fontsource/geist-sans | MIT | https://fontsource.org |
| @fontsource/ibm-plex-mono | MIT | https://fontsource.org |
| @fontsource/ibm-plex-sans | MIT | https://fontsource.org |

### Dev dependencies

| Package | License | Homepage |
|---------|---------|---------|
| vite | MIT | https://vite.dev |
| @vitejs/plugin-react | MIT | https://github.com/vitejs/vite-plugin-react |
| @tailwindcss/vite | MIT | https://tailwindcss.com |
| typescript | Apache-2.0 | https://www.typescriptlang.org |
| oxlint | MIT | https://oxc.rs/docs/guide/usage/linter |
| puppeteer-core | Apache-2.0 | https://pptr.dev |
| @types/react | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped |
| @types/react-dom | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped |
| @types/node | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped |

---

## 4. Standards & Methodologies Referenced

| Standard | Owner | URL |
|---------|-------|-----|
| CVSS v3.1 | FIRST.org | https://www.first.org/cvss/ |
| OWASP Top 10 (2021) | OWASP Foundation | https://owasp.org/Top10/ |
| CWE (Common Weakness Enumeration) | MITRE Corporation | https://cwe.mitre.org |
| OWASP API Security Top 10 | OWASP Foundation | https://owasp.org/www-project-api-security/ |

These standards and their associated content are the property of their respective
organizations. Their inclusion by reference does not imply endorsement.

---

## 5. Datasets & Content

All data in `lab/seed.py` — including usernames, email addresses, API tokens,
recovery codes, IP addresses, report content, satellite identifiers, station
codes, and coordinates — is **entirely fictional and synthetic**. It does not
represent any real person, organization, system, or classified information.

---

## 6. Trademark Notice

"World Monitor" is referenced as the subject of this academic assessment.
This project has no affiliation with, and is not endorsed by, any organization
operating under that name. All use of the name is solely for identification
purposes within the SIH26163 problem statement context.
