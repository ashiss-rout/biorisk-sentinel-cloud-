import importlib
import unittest


class PrototypeIntegrationTests(unittest.TestCase):
    def test_teammate_scoring_module_is_safe_to_import(self):
        module = importlib.import_module("scoring")

        self.assertTrue(callable(module.calculate_reliability))
        self.assertEqual(module.calculate_reliability.__module__, "services.scoring")

    def test_teammate_risk_engine_is_reference_only_and_import_safe(self):
        module = importlib.import_module("biometric_risk_engine")

        self.assertTrue(hasattr(module, "BiometricRiskEngine"))
        self.assertIn("reference only", module.__doc__.lower())


if __name__ == "__main__":
    unittest.main()
