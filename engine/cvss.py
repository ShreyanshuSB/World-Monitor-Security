"""
CVSS v3.1 Calculator and Vector Parser
Accurate implementation of FIRST CVSS v3.1 Base Score equations and severity ratings.
"""

import math
from typing import Dict, Any, Tuple

class CVSS31Calculator:
    # Metric Weight Definitions
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

    @staticmethod
    def roundup(input_val: float) -> float:
        int_input = round(input_val * 100000)
        if int_input % 10000 == 0:
            return int_input / 100000.0
        else:
            return (math.floor(int_input / 10000) + 1) / 10.0

    @classmethod
    def parse_vector(cls, vector_str: str) -> Dict[str, str]:
        parts = vector_str.strip().split("/")
        metrics = {}
        for p in parts:
            if not p:
                continue
            if ":" in p:
                k, v = p.split(":", 1)
                metrics[k] = v
        return metrics

    @classmethod
    def calculate(cls, vector_str: str) -> Dict[str, Any]:
        metrics = cls.parse_vector(vector_str)
        
        av = metrics.get("AV", "N")
        ac = metrics.get("AC", "L")
        pr = metrics.get("PR", "N")
        ui = metrics.get("UI", "N")
        scope = metrics.get("S", "U")
        c = metrics.get("C", "N")
        i = metrics.get("I", "N")
        a = metrics.get("A", "N")

        av_val = cls.AV_WEIGHTS.get(av, 0.85)
        ac_val = cls.AC_WEIGHTS.get(ac, 0.77)
        pr_val = cls.PR_WEIGHTS[scope].get(pr, 0.85)
        ui_val = cls.UI_WEIGHTS.get(ui, 0.85)

        c_val = cls.CIA_WEIGHTS.get(c, 0.0)
        i_val = cls.CIA_WEIGHTS.get(i, 0.0)
        a_val = cls.CIA_WEIGHTS.get(a, 0.0)

        # 1. ISS (Impact Sub Score)
        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

        # 2. Impact
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow((iss - 0.02), 15)

        # 3. Exploitability
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # 4. Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if scope == "U":
                base_score = cls.roundup(min(impact + exploitability, 10.0))
            else:
                base_score = cls.roundup(min(1.08 * (impact + exploitability), 10.0))

        # 5. Severity Rating
        if base_score == 0.0:
            severity = "NONE"
        elif base_score <= 3.9:
            severity = "LOW"
        elif base_score <= 6.9:
            severity = "MEDIUM"
        elif base_score <= 8.9:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        return {
            "vector": vector_str,
            "base_score": round(base_score, 1),
            "severity": severity,
            "impact_subscore": round(impact, 2),
            "exploitability_subscore": round(exploitability, 2),
            "metrics": {
                "AV": av,
                "AC": ac,
                "PR": pr,
                "UI": ui,
                "S": scope,
                "C": c,
                "I": i,
                "A": a
            }
        }
