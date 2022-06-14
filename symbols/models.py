from django.db import models
import os
import shutil
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
        super(Symbols, self).save(*args, **kwargs)
        name = os.path.basename(self.symbols_file.name)
        if self.os == "Windows":
            new_path = '/'.join([UPLOAD_PATH, str(self.id),"windows",name])
            vol_path = '/'.join([UPLOAD_PATH, str(self.id)])
        else:
            new_path = '/'.join([UPLOAD_PATH, str(self.id),"linux",name])
            vol_path = '/'.join([UPLOAD_PATH, str(self.id)])
        if not os.path.exists(os.path.dirname(new_path)):
            os.makedirs(os.path.dirname(new_path))
        os.rename(self.symbols_file.name, new_path)
        self.symbols_file.name = new_path
        super(Symbols, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        path = os.sep.join(self.symbols_file.name.split(os.sep)[:-2])
        shutil.rmtree(path)
        super(Symbols, self).delete(*args, **kwargs)
