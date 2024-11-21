from django.contrib import admin

# Register your models here.
from .models import VolatilityPlugin, EnrichedProcess

admin.site.register(VolatilityPlugin)
admin.site.register(EnrichedProcess)
