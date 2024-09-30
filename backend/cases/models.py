from django.db import models
from django.contrib.auth.models import User


class Case(models.Model):
    bucket_id = models.UUIDField()
    name = models.CharField(max_length=500)
    description = models.TextField()
    linked_users = models.ManyToManyField(User)
    last_update = models.DateField(auto_now=True)
    def __str__(self):
        return self.name
