import unittest

from mangopanel.security import create_jwt, hash_password, totp_code, verify_jwt, verify_password, verify_totp


class SecurityTests(unittest.TestCase):
    def test_password_hash_roundtrip(self):
        encoded = hash_password("secret")
        self.assertTrue(verify_password("secret", encoded))
        self.assertFalse(verify_password("wrong", encoded))

    def test_jwt_roundtrip(self):
        token = create_jwt({"sub": 1, "purpose": "test"}, "secret", 60)
        payload = verify_jwt(token, "secret")
        self.assertEqual(payload["sub"], 1)
        self.assertIsNone(verify_jwt(token, "wrong"))

    def test_totp_roundtrip(self):
        secret = "JBSWY3DPEHPK3PXP"
        code = totp_code(secret)
        self.assertTrue(verify_totp(secret, code))


if __name__ == "__main__":
    unittest.main()

