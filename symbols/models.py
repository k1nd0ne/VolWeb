from django.db import models
import os as los
CHOICES = (
        ('Windows', 'Windows'),
        ('Linux', 'Linux'),
#        ('MacOs', 'MacOs'), <- not implemented yet
    )

UPLOAD_PATH = "symbols/uploads"

class Symbols(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    os = models.CharField(max_length=50, choices = CHOICES)
    description = models.TextField(max_length=500)
    symbols_file = models.FileField(upload_to=UPLOAD_PATH,)
    def __str__(self):
        return str(self.name)
    def save(self, *args, **kwargs):
    # Call standard save
        super(Symbols, self).save(*args, **kwargs)
        name = los.path.basename(self.symbols_file.name)
        if self.os == "Windows":
            new_path = '/'.join([UPLOAD_PATH, str(self.id),"windows",name])
            vol_path = '/'.join([UPLOAD_PATH, str(self.id)])
        else:
            new_path = '/'.join([UPLOAD_PATH, str(self.id),"linux",name])
            vol_path = '/'.join([UPLOAD_PATH, str(self.id)])

        los.makedirs(los.path.dirname(new_path))
        los.rename(self.symbols_file.name, new_path)
        self.symbols_file.name = new_path
        super(Symbols, self).save(*args, **kwargs)
