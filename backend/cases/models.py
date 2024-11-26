from django.db import models
from django.contrib.auth.models import User
import uuid


class Case(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=500, unique=True)
    description = models.TextField()
    linked_users = models.ManyToManyField(User)
    last_update = models.DateField(auto_now=True)

    def __str__(self):
        return self.name


class UploadSession(models.Model):
    upload_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    filename = models.CharField(max_length=255)
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    os = models.CharField(max_length=50, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.upload_id)
