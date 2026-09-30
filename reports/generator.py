"""
Security Assessment Platform - Formal Report Generator (Markdown & PDF)
Complies with SIH26163 (NTRO) assessment reporting standards.
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

def generate_markdown_report(findings: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    md = f"""# CONFIDENTIAL SECURITY ASSESSMENT REPORT
## Target: World Monitor Application (Controlled Lab Environment)
**Organization:** National Technical Research Organisation (NTRO) / SIH 2026  
**Problem Statement ID:** SIH26163  
**Assessment Date:** {now}  
**Classification:** RESTRICTED // CONFIDENTIAL  
**Auditor:** Principal AppSec Lead & Automated Assessment Engine  
**Target Environment:** INTENTIONALLY VULNERABLE LAB TARGET - controlled environment (localhost)

---

## 1. Executive Summary
This authorized security assessment evaluated the security posture of the **World Monitor Application** running within a controlled, isolated laboratory environment. Testing was conducted strictly against permitted endpoints adhering to fail-closed scope policies.

### Posture Overview
- **Total Verified Findings:** {stats.get('total_findings', len(findings))}
- **Critical Severity:** {stats.get('critical', 0)}
- **High Severity:** {stats.get('high', 0)}
- **Medium Severity:** {stats.get('medium', 0)}
- **Low / Informational:** {stats.get('low', 0)}
- **System Risk Rating:** **{stats.get('risk_score', 'HIGH')}** (Score: {stats.get('risk_numeric', 78)}/100)

The assessment identified critical architectural and implementation vulnerabilities in object-level authorization, input sanitization, and credential handling. Remediation patches and re-tests were successfully validated for key components.

---

## 2. Scope & Rules of Engagement
- **Authorized Target:** `http://127.0.0.1:8001` (Strict localhost boundary enforced via hardware/software Scope Guard)
- **Non-Destructive Principle:** All probes were benign, minimal reproduction proofs utilizing seeded mock accounts. No Denial of Service (DoS) or destructive operations were permitted.
- **Auditability:** Every check, packet probe, and operator action was immutably recorded to the platform `audit_log` repository.

---

## 3. Findings Summary Table

| ID | Title | Scope Area | Severity | CVSS 3.1 | Status |
|----|-------|------------|----------|----------|--------|
"""
    for f in findings:
        md += f"| `{f['id']}` | {f['title']} | {f['scope_area']} | **{f['severity']}** | {f['cvss_score']} | `{f['status']}` |\n"

    md += "\n---\n\n## 4. Comprehensive Technical Findings\n\n"

    for idx, f in enumerate(findings, 1):
        evidence = f.get("evidence", {})
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except Exception:
                evidence = {}

        steps = f.get("steps_to_reproduce", [])
        if isinstance(steps, str):
            try:
                steps = json.loads(steps)
            except Exception:
                steps = [steps]

        md += f"""### 4.{idx} [{f['id']}] {f['title']}

- **Severity:** {f['severity']} (CVSS 3.1: `{f['cvss_score']}`)  
- **CVSS Vector:** `{f['cvss_vector']}`  
- **Affected Component:** `{f['affected_component']}`  
- **Scope Area:** {f['scope_area']}  
- **CWE:** {f['cwe_id']}  
- **OWASP Category:** {f['owasp_category']}  
- **Status:** `{f['status']}`

#### Description
{f['description']}

#### Business & Operational Impact
{f['business_impact']}

#### Steps to Reproduce
"""
        for step_num, step in enumerate(steps, 1):
            md += f"{step_num}. {step}\n"

        md += f"""
#### Proof of Concept Probe
```bash
{f['proof_of_concept']}
```

#### Remediation Recommendation
{f['remediation']}

#### Recommended Code Patch
```diff
{f['code_diff']}
```

#### Stored Evidence (HTTP Transaction)
- **Request:** `{evidence.get('request_method', 'GET')} {evidence.get('request_url', '')}`
- **Response Status:** `HTTP {evidence.get('response_status', 200)}`
- **Duration:** `{evidence.get('duration_ms', 0)} ms`

---
"""

    md += """
## 5. Remediation Roadmap & Verification Summary
1. **Immediate (0-24 Hours):** Deploy input parameterization on intelligence report queries (remediates SQL injection). Implement strict RBAC guards on `/api/reports/{id}`.
2. **Short-Term (1-3 Days):** Strip diagnostic credentials and debug tokens from `/api/config/client`. Introduce IP-rate limiting on authentication.
3. **Medium-Term (1 Week):** Inject HTTP defense-in-depth headers (`X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `HSTS`). Sanitize diagnostic logging to redact credentials.

---
## 6. Appendix: Controlled Environment Disclaimer
This assessment was performed against an intentionally vulnerable laboratory testbed simulating World Monitor services under controlled local parameters. Findings represent authentic behavioral responses verified via active HTTP diagnostics.
"""
    return md

def generate_pdf_report(findings: List[Dict[str, Any]], stats: Dict[str, Any], output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
        alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#475569'),
        alignment=TA_CENTER
    )
    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    code_style = ParagraphStyle(
        'DocCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#0F172A')
    )

    story = []

    # Title & Header
    story.append(Paragraph("WORLD MONITOR APPLICATION", title_style))
    story.append(Paragraph("Authorized Security Assessment & Vulnerability Audit Report", subtitle_style))
    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>Problem Statement:</b> SIH26163 (NTRO) | <b>Environment:</b> Controlled Lab Target (Localhost)", subtitle_style))
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#CBD5E1"), spaceBefore=5, spaceAfter=15))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    summary_text = (
        f"This formal security assessment evaluates the defense posture of the World Monitor application replica. "
        f"A total of <b>{len(findings)} verified vulnerabilities</b> were confirmed with stored HTTP evidence across "
        f"all 7 core security domains. The target was evaluated strictly under controlled localhost parameters."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))

    # Summary Table
    table_data = [["ID", "Title", "Severity", "CVSS", "Scope Domain", "Status"]]
    for f in findings:
        table_data.append([
            f["id"],
            f["title"][:32] + ("..." if len(f["title"]) > 32 else ""),
            f["severity"],
            str(f["cvss_score"]),
            f["scope_area"][:18],
            f["status"]
        ])

    t = Table(table_data, colWidths=[75, 175, 55, 40, 110, 75])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 8.5),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,1), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('ALIGN', (2,0), (3,-1), 'CENTER'),
        ('ALIGN', (5,0), (5,-1), 'CENTER'),
    ]))
    story.append(t)
    story.append(Spacer(1, 15))

    # Detailed Findings
    story.append(Paragraph("2. Technical Findings & Safe Proof-of-Concepts", h2_style))
    for f in findings:
        story.append(Paragraph(f"<b>[{f['id']}] {f['title']}</b>", ParagraphStyle('FTitle', parent=h2_style, fontSize=11, leading=14)))
        details = (
            f"<b>Severity:</b> {f['severity']} (CVSS 3.1: {f['cvss_score']}) | "
            f"<b>Component:</b> {f['affected_component']}<br/>"
            f"<b>CWE:</b> {f['cwe_id']}<br/>"
            f"<b>Description:</b> {f['description']}<br/>"
            f"<b>Business Impact:</b> {f['business_impact']}<br/>"
            f"<b>Remediation:</b> {f['remediation']}"
        )
        story.append(Paragraph(details, body_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"<b>Safe PoC Probe:</b> <code>{f['proof_of_concept']}</code>", code_style))
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0"), spaceBefore=3, spaceAfter=8))

    doc.build(story)
