from django.db import models
from cases.models import Case

OS = (
    ('Windows', 'Windows'),
    ('Linux', 'Linux'),
#   ('MacOs', 'MacOs'), <- not implemented yet
)
class Evidence(models.Model):
    dump_id = models.AutoField(primary_key=True)
    dump_name = models.CharField(max_length=250)
    dump_os = models.CharField(max_length=10, choices=OS)
    dump_linked_case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        null=False
    )
    dump_status =  models.IntegerField(default=0)
    def __str__(self):
        return str(self.dump_name)