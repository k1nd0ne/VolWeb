from django.db import models
from django.contrib.auth.models import User


class Case(models.Model):
    case_id = models.AutoField(primary_key=True)
    case_bucket_id = models.UUIDField()
    case_name = models.CharField(max_length=500)
    case_description = models.TextField()
    linked_users = models.ManyToManyField(User)
    case_last_update = models.DateField(auto_now=True)

    def __str__(self):
        return self.case_name
