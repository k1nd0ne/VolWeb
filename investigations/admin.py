from django.contrib import admin
from .models import UploadInvestigation, Activity, ProcessDump, FileDump
admin.site.register(UploadInvestigation)
admin.site.register(Activity)
admin.site.register(ProcessDump)
admin.site.register(FileDump)
