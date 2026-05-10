from django.contrib import admin

# Register your models here.
import logging
from .models import Election, Candidate, Vote

logging.basicConfig(level=logging.INFO)
logging.info("Registering models with Django admin.")
admin.site.register(Election)
admin.site.register(Candidate)
admin.site.register(Vote)