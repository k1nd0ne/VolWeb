from django.db import models

CHOICES = (
        ('Windows', 'Windows'),
        ('Linux', 'Linux'),
#        ('MacOs', 'MacOs'), <- not implemented yet
    )

class Symbols(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    os = models.CharField(max_length=50, choices = CHOICES)
    description = models.TextField(max_length=500)
    symbols_file = models.FileField(upload_to="symbols/uploads/",)
    def __str__(self):
        return str(self.name)
