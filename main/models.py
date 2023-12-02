from django.db import models
from django.contrib.auth.models import User


# class ImageSignature(models.Model):
#     investigation = models.ForeignKey(
#         Case,
#         on_delete=models.CASCADE,
#     )
#     md5 = models.CharField(max_length=32, null=True)
#     sha1 = models.CharField(max_length=40, null=True)
#     sha256 = models.CharField(max_length=64, null=True)
