"""Standalone teammate prototype retained for reference only.

This module is not part of the Flask assessment workflow. Its configuration
fields, weights, thresholds, and access-decision language do not match the
canonical aggregate assessment contract in ``services.scoring``. It is kept
import-safe for coursework comparison, but application code must not call it.
"""

import json
from typing import Dict, Any, Tuple

class BiometricRiskEngine:
    """
    Biometric Security Assessment Engine
    Calculates Reliability (S_R), Privacy (S_P), Attack Resistance (S_A),
    Composite Security Score (S_comp), and outputs Risk-Aware Authentication Decisions.
    """

    WEIGHTS = {
        "reliability": 0.30,
        "privacy": 0.35,
        "attack_resistance": 0.35
    }

    DECISION_THRESHOLDS = {
        "allow": 85.0,
        "step_up": 65.0
    }

    def __init__(self):
        pass

    def _calculate_reliability(self, config: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
        fmr_val = config.get("fmr", 1e-4)
        fnmr_val = config.get("fnmr", 2.0)
        demo_val = config.get("demographic_variance", 2.0)

        # FMR Deduction
        if fmr_val <= 1e-5:
            d_fmr = 0.0
        elif fmr_val <= 1e-4:
            d_fmr = -15.0
        else:
            d_fmr = -35.0

        # FNMR Deduction
        if fnmr_val <= 1.0:
            d_fnmr = 0.0
        elif fnmr_val <= 3.0:
            d_fnmr = -10.0
        else:
            d_fnmr = -20.0

        # Demographic Variance Deduction
        if demo_val <= 1.0:
            d_demo = 0.0
        elif demo_val <= 5.0:
            d_demo = -15.0
        else:
            d_demo = -30.0

        score = max(0.0, min(100.0, 100.0 + d_fmr + d_fnmr + d_demo))
        breakdown = {
            "d_fmr": d_fmr,
            "d_fnmr": d_fnmr,
            "d_demo": d_demo,
            "subtotal": score
        }
        return score, breakdown

    def _calculate_privacy(self, config: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
        template_prot = config.get("template_protection", "raw_image")
        storage_loc = config.get("storage_location", "central_unsegregated")
        revocable = config.get("revocable", False)

        # Template Protection Base Score
        prot_map = {
            "raw_image": 10.0,
            "aes256_vector": 50.0,
            "cancelable": 80.0,
            "homomorphic_zkp": 100.0
        }
        base_prot = prot_map.get(template_prot, 10.0)

        # Storage Location Modifier
        storage_map = {
            "central_unsegregated": -30.0,
            "central_segregated": -15.0,
            "edge_hardware_se": 0.0
        }
        mod_storage = storage_map.get(storage_loc, -30.0)

        # Revocability Modifier
        mod_revocable = 0.0 if revocable else -15.0

        score = max(0.0, min(100.0, base_prot + mod_storage + mod_revocable))
        breakdown = {
            "base_template_protection": base_prot,
            "mod_storage_location": mod_storage,
            "mod_revocability": mod_revocable,
            "subtotal": score
        }
        return score, breakdown

    def _calculate_attack_resistance(self, config: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
        pad_level = config.get("pad_level", "none")
        anti_inject = config.get("anti_injection", "unsigned_software")
        channel_sec = config.get("channel_security", "plaintext_legacy_tls")

        # PAD Deductions
        pad_map = {
            "none": -50.0,
            "level_1": -30.0,
            "level_2": -15.0,
            "level_3": 0.0
        }
        d_pad = pad_map.get(pad_level, -50.0)

        # Injection Deductions
        inject_map = {
            "unsigned_software": -30.0,
            "hardware_signed_attestation": 0.0
        }
        d_inject = inject_map.get(anti_inject, -30.0)

        # Channel Deductions
        channel_map = {
            "plaintext_legacy_tls": -40.0,
            "tls13_mtls_pinned": 0.0
        }
        d_channel = channel_map.get(channel_sec, -40.0)

        score = max(0.0, min(100.0, 100.0 + d_pad + d_inject + d_channel))
        breakdown = {
            "d_pad": d_pad,
            "d_injection": d_inject,
            "d_channel": d_channel,
            "subtotal": score
        }
        return score, breakdown

    def evaluate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates system configuration and returns composite risk assessment.
        """
        # Calculate Dimensions
        s_r, r_breakdown = self._calculate_reliability(config)
        s_p, p_breakdown = self._calculate_privacy(config)
        s_a, a_breakdown = self._calculate_attack_resistance(config)

        # Check Hard-Fail Triggers
        hard_fail_reasons = []
        if s_a < 40.0:
            hard_fail_reasons.append("Attack Resistance Score (S_A) fell below critical threshold (< 40)")
        if config.get("template_protection") == "raw_image":
            hard_fail_reasons.append("Critical Failure: Raw biometric images stored without encryption")
        if config.get("channel_security") == "plaintext_legacy_tls":
            hard_fail_reasons.append("Critical Failure: Insecure/Unpinned transport channel")

        is_hard_fail = len(hard_fail_reasons) > 0

        # Calculate Composite Score
        s_comp = (self.WEIGHTS["reliability"] * s_r) + \
                 (self.WEIGHTS["privacy"] * s_p) + \
                 (self.WEIGHTS["attack_resistance"] * s_a)
        s_comp = round(s_comp, 2)

        # Risk-Aware Decision Function
        if is_hard_fail or s_comp < self.DECISION_THRESHOLDS["step_up"]:
            decision = "DENY ACCESS"
            trust_level = "CRITICAL_RISK"
        elif s_comp < self.DECISION_THRESHOLDS["allow"]:
            decision = "STEP_UP_MFA"
            trust_level = "MODERATE_RISK"
        else:
            decision = "ALLOW ACCESS"
            trust_level = "HIGH_TRUST"

        return {
            "composite_score": s_comp,
            "decision": decision,
            "trust_level": trust_level,
            "hard_fail": {
                "triggered": is_hard_fail,
                "reasons": hard_fail_reasons
            },
            "scores": {
                "reliability": s_r,
                "privacy": s_p,
                "attack_resistance": s_a
            },
            "detailed_breakdown": {
                "reliability": r_breakdown,
                "privacy": p_breakdown,
                "attack_resistance": a_breakdown
            }
        }


# ==========================================
# USER INPUT TERMINAL WIZARD
# ==========================================
def get_user_config() -> Dict[str, Any]:
    print("\n" + "="*50)
    print("🛡️ BIO-RISK SENTINEL - CONFIGURATION WIZARD 🛡️")
    print("="*50)
    
    config = {}
    
    try:
        # 1. Reliability Inputs
        print("\n--- 1. Reliability & Accuracy ---")
        config["fmr"] = float(input("Enter False Match Rate (FMR) (e.g., 0.0001): "))
        config["fnmr"] = float(input("Enter False Non-Match Rate (FNMR) % (e.g., 2.0): "))
        config["demographic_variance"] = float(input("Enter Demographic Variance % (e.g., 1.5): "))
        
        # 2. Privacy Inputs
        print("\n--- 2. Privacy & Data Handling ---")
        print("1: raw_image")
        print("2: aes256_vector")
        print("3: cancelable")
        print("4: homomorphic_zkp")
        tp_map = {"1": "raw_image", "2": "aes256_vector", "3": "cancelable", "4": "homomorphic_zkp"}
        config["template_protection"] = tp_map.get(input("Select Template Protection (1-4): "), "raw_image")

        print("\n1: central_unsegregated")
        print("2: central_segregated")
        print("3: edge_hardware_se")
        sl_map = {"1": "central_unsegregated", "2": "central_segregated", "3": "edge_hardware_se"}
        config["storage_location"] = sl_map.get(input("Select Storage Location (1-3): "), "central_unsegregated")

        config["revocable"] = input("\nIs the biometric template revocable? (y/n): ").strip().lower() == 'y'

        # 3. Attack Resistance Inputs
        print("\n--- 3. Attack Resistance ---")
        print("1: none")
        print("2: level_1 (Basic)")
        print("3: level_2 (Texture)")
        print("4: level_3 (Depth/IR)")
        pad_map = {"1": "none", "2": "level_1", "3": "level_2", "4": "level_3"}
        config["pad_level"] = pad_map.get(input("Select PAD/Liveness Level (1-4): "), "none")

        print("\n1: unsigned_software")
        print("2: hardware_signed_attestation")
        ai_map = {"1": "unsigned_software", "2": "hardware_signed_attestation"}
        config["anti_injection"] = ai_map.get(input("Select Anti-Injection Mechanism (1-2): "), "unsigned_software")

        print("\n1: plaintext_legacy_tls")
        print("2: tls13_mtls_pinned")
        cs_map = {"1": "plaintext_legacy_tls", "2": "tls13_mtls_pinned"}
        config["channel_security"] = cs_map.get(input("Select Channel Security (1-2): "), "plaintext_legacy_tls")

    except ValueError:
        print("\n❌ Invalid number format entered. Defaulting to high-risk values for numeric fields.")
        config["fmr"] = 1e-3
        config["fnmr"] = 4.0
        config["demographic_variance"] = 6.0

    return config

# ==========================================
# EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
    engine = BiometricRiskEngine()
    
    # Run the interactive input wizard
    user_config = get_user_config()
    
    # Evaluate the user's input
    result = engine.evaluate(user_config)
    
    # Print the final output
    print("\n" + "="*50)
    print("📊 FINAL SECURITY ASSESSMENT REPORT 📊")
    print("="*50)
    print(json.dumps(result, indent=4))