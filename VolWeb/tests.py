from django.test import TestCase
from VolWeb.keyconfig import Database, Secrets

class EnvVariablesTestCase(TestCase):

    def test_mandatory_envar(self):
        self.assertNotEqual(Secrets.AWS_ACCESS_KEY_ID, None)
        self.assertNotEqual(Secrets.AWS_SECRET_ACCESS_KEY, None)
        self.assertNotEqual(Secrets.AWS_ENDPOINT_URL, None)
        self.assertNotEqual(Database.HOST, None)
        self.assertNotEqual(Database.NAME, None)
        self.assertNotEqual(Database.PORT, None)
        self.assertNotEqual(Database.PASSWORD, None)
        self.assertNotEqual(Database.USER, None)
