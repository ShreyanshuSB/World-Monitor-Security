"""
World Monitor Lab - Vulnerability Configuration System
Controls active vulnerabilities in the intentionally vulnerable target.
Allows dynamic patching and re-testing to demonstrate before/after evidence.
"""

from typing import Dict, Any

class VulnerabilityConfig:
    def __init__(self):
        # Default state: All seeded vulnerabilities are ACTIVE
        self.patches: Dict[str, bool] = {
            "AUTH_WEAK_SECRET": False,      # Weak JWT signing key
            "AUTHZ_IDOR_REPORT": False,     # IDOR on /api/reports/{id}
            "AUTHZ_BFLA_EXPORT": False,     # Missing role check on /api/admin/telemetry-export
            "INPUT_SQLI_SEARCH": False,     # SQL Injection on /api/reports?search=
            "INPUT_STORED_XSS": False,      # Stored XSS on report notes
            "API_EXCESSIVE_DATA": False,    # Excessive data exposure in user profile
            "API_NO_RATE_LIMIT": False,     # Lack of rate limiting on login
            "CLIENT_KEY_LEAK": False,       # Sensitive gateway key in /api/config/client
            "COMM_MISSING_HEADERS": False,  # Missing security headers
            "DATA_CLEARTEXT_LOGS": False,   # Cleartext tokens in debug logs
        }

    def is_fixed(self, vuln_key: str) -> bool:
        return self.patches.get(vuln_key, False)

    def apply_fix(self, vuln_key: str) -> bool:
        if vuln_key in self.patches:
            self.patches[vuln_key] = True
            return True
        return False

    def reset_fix(self, vuln_key: str) -> bool:
        if vuln_key in self.patches:
            self.patches[vuln_key] = False
            return True
        return False

    def get_status(self) -> Dict[str, bool]:
        return self.patches.copy()

vuln_config = VulnerabilityConfig()
