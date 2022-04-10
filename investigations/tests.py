from django.test import TestCase
from investigations.models import *


class UploadInvestigationTestCase(TestCase):
    def setUp(self):
        UploadInvestigation.objects.create(title="TestCase", os_version="Windows", investigators="user", description="test case description", status="0", taskid="0", existingPath="c131ce77-a803-4617-af67-1d126e094960_Windows_7.dmp", name="c131ce77-a803-4617-af67-1d126e094960_Windows_7.dmp", eof=True, uid="c131ce77-a803-4617-af67-1d126e094960")

# Create your tests here.
