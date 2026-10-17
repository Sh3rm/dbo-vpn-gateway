import base64
import unittest

from dbovpn import totp

# RFC 6238 appendix B, SHA1 seed "12345678901234567890", 8 digits.
RFC_KEY = b"12345678901234567890"
RFC_VECTORS = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
               (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]
SECRET = base64.b32encode(RFC_KEY).decode()


class TotpTest(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for t, expected in RFC_VECTORS:
            self.assertEqual(totp.hotp(RFC_KEY, t // 30, digits=8), expected, t)

    def test_six_digit_code_is_rfc_value_truncated(self):
        self.assertEqual(totp.code_at(SECRET, 59), "287082")

    def test_window_accepts_plus_minus_one_step(self):
        now = 1111111111
        for offset in (-30, 0, 30):
            code = totp.code_at(SECRET, now + offset)
            self.assertIsNotNone(totp.verify(SECRET, code, now), offset)

    def test_window_rejects_two_steps(self):
        now = 1111111111
        for offset in (-60, 60):
            self.assertIsNone(totp.verify(SECRET, totp.code_at(SECRET, now + offset), now), offset)

    def test_returns_matching_counter(self):
        now = 1111111111
        self.assertEqual(totp.verify(SECRET, totp.code_at(SECRET, now - 30), now), now // 30 - 1)

    def test_replay_rejected(self):
        now = 1111111111
        code = totp.code_at(SECRET, now)
        counter = totp.verify(SECRET, code, now, last_counter=0)
        self.assertIsNotNone(counter)
        self.assertIsNone(totp.verify(SECRET, code, now, last_counter=counter))
        self.assertIsNone(totp.verify(SECRET, code, now + 25, last_counter=counter))

    def test_older_step_rejected_after_newer_used(self):
        now = 1111111111
        newer = totp.verify(SECRET, totp.code_at(SECRET, now + 30), now)
        self.assertIsNone(totp.verify(SECRET, totp.code_at(SECRET, now), now, last_counter=newer))

    def test_malformed_codes(self):
        for code in ("", "12345", "1234567", "abcdef", None, " 12 34"):
            self.assertIsNone(totp.verify(SECRET, code, 59))

    def test_bad_secret(self):
        self.assertIsNone(totp.verify("not base32 !!", "123456", 59))

    def test_generated_secret(self):
        s = totp.generate_secret()
        self.assertEqual(len(s), 32)
        self.assertEqual(len(base64.b32decode(s)), 20)

    def test_provisioning_uri(self):
        uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "ali.veli", "Example Corp VPN")
        self.assertTrue(uri.startswith("otpauth://totp/Example%20Corp%20VPN%3Aali.veli?"))
        self.assertIn("secret=JBSWY3DPEHPK3PXP", uri)
        self.assertIn("issuer=Example%20Corp%20VPN", uri)
        self.assertIn("period=30", uri)
        self.assertIn("digits=6", uri)


if __name__ == "__main__":
    unittest.main()
