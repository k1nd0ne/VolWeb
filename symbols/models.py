from django.db import models
import os
import shutil

CHOICES = (
    ('Windows', 'Windows'),
    ('Linux', 'Linux'),
    #        ('MacOs', 'MacOs'), <- not implemented yet
)

UPLOAD_PATH = "symbols/"

class Symbol(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    os = models.CharField(max_length=50, choices=CHOICES)
    description = models.TextField(max_length=500)
    symbols_file = models.FileField(upload_to=UPLOAD_PATH)

    def __str__(self):
        return str(self.name)

    def save(self, *args, **kwargs):
        super(Symbol, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if self.symbols_file:
            self.symbols_file.delete()
        super(Symbol, self).delete(*args, **kwargs)
