from django.contrib import admin

# Register your models here.
from .models import SecurityEvent, BlockedIP   
admin.site.register(SecurityEvent)
admin.site.register(BlockedIP) 