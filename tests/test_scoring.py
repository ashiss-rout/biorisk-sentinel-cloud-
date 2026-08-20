import unittest

from services.scoring import (
    AttackInput,
    PrivacyInput,
    ReliabilityInput,
    calculate_attack_resistance,
    calculate_overall,
    calculate_privacy,
    calculate_reliability,
)


class ScoringTests(unittest.TestCase):
    def test_demo_reliability_score_rounds_to_expected_value(self):
        result = calculate_reliability(
            ReliabilityInput(100000, 96500, 3500, 20, 3480, 98000, 2000, 1.2)
        )
        self.assertEqual(result.far, 1.0)
        self.assertEqual(result.frr, 3.55)
        self.assertEqual(result.accuracy, 96.5)
        self.assertEqual(round(result.score), 88)

    def test_privacy_score(self):
        score = calculate_privacy(
            PrivacyInput(True, True, False, True, True, False, True, True, True, True)
        )
        self.assertEqual(score, 90.0)

    def test_attack_resistance_and_risk_band(self):
        score, results = calculate_attack_resistance(
            [AttackInput("Replay", 100, 97), AttackInput("Spoofing", 100, 84)]
        )
        self.assertEqual(score, 90.5)
        self.assertEqual(results[0].risk_level, "Low")
        self.assertEqual(results[1].risk_level, "High")

    def test_raw_data_triggers_urgent_review(self):
        result = calculate_overall(
            90, 90, 90,
            template_encrypted=True,
            raw_data_stored=True,
            spoof_detection_rate=95,
            far=0.1,
            mfa_enabled=True,
            audit_logging_enabled=True,
        )
        self.assertEqual(result.risk_level, "Low")
        self.assertTrue(result.urgent_review_required)
        self.assertIn("Raw biometric data is stored.", result.override_reasons)


if __name__ == "__main__":
    unittest.main()
