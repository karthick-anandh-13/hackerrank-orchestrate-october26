import unittest
from code.identity import IdentityResolver

class TestIdentityResolver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver(
            identities_path='dataset/user_identities.csv',
            audit_log_path='dataset/user_audit_log.csv'
        )

    def test_resolve_by_email_direct(self):
        email = 'amina.elmasri@gmail.com'
        identity = self.resolver.resolve_by_email(email)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.user_id, 'user_01')

    def test_resolve_by_user_id(self):
        user_id = 'user_09'
        identity = self.resolver.resolve_by_user_id(user_id)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.email, 'kwame-mensah@proton.me')

    def test_resolve_by_any_identifier_phone(self):
        phone = '+1 (202) 555-0103'
        identity = self.resolver.resolve_by_any_identifier(phone)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.user_id, 'user_03')

    def test_resolve_historical_email(self):
        # Historical email for user_10 before change
        old_email = 'nadia.ionescu@yahoo.com'
        identity = self.resolver.resolve_by_email(old_email)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.user_id, 'user_10')
        # A uniquely owned retired email remains useful to find data remanence.
        self.assertTrue(identity.identifier_valid_at('email', old_email, '2026-09-01T00:00:00Z'))

    def test_resolve_historical_phone(self):
        # Historical phone for user_400 before change
        old_phone = '+27 72 156 3064'
        identity = self.resolver.resolve_by_any_identifier(old_phone)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.user_id, 'user_400')

    def test_unknown_identifiers(self):
        self.assertIsNone(self.resolver.resolve_by_user_id('user_999'))
        self.assertIsNone(self.resolver.resolve_by_email('nonexistent@example.com'))
        self.assertIsNone(self.resolver.resolve_by_any_identifier('unknown_identifier'))
if __name__ == '__main__':
    unittest.main()
