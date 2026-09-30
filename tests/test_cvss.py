"""
Unit Tests for CVSS v3.1 Calculator
Validates mathematical equations, rounding logic, and severity thresholds against standard vectors.
"""

from engine.cvss import CVSS31Calculator

def test_cvss_critical_vector():
    # Standard Critical SQLi vector: Network, Low complexity, No privileges, No UI, Scope Unchanged, High CIA
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    result = CVSS31Calculator.calculate(vector)
    assert result["base_score"] == 9.8
    assert result["severity"] == "CRITICAL"

def test_cvss_high_idor_vector():
    # IDOR vector: Network, Low complexity, Low privilege, No UI, Scope Unchanged, High Conf
    vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    result = CVSS31Calculator.calculate(vector)
    assert result["base_score"] == 6.5
    assert result["severity"] == "MEDIUM"

def test_cvss_scope_changed_xss():
    # Stored XSS with Scope Changed
    vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
    result = CVSS31Calculator.calculate(vector)
    assert result["severity"] in ["MEDIUM", "HIGH"]
    assert result["base_score"] > 5.0

def test_cvss_roundup():
    assert CVSS31Calculator.roundup(4.0) == 4.0
    assert CVSS31Calculator.roundup(4.01) == 4.1
    assert CVSS31Calculator.roundup(9.8) == 9.8
