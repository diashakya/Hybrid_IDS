from django.db import models
from django.conf import settings
from django.db import models


# Create your models here.
class Election(models.Model):
    title = models.CharField(max_length=200)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

class Candidate(models.Model):
    election = models.ForeignKey(Election, on_delete=models.CASCADE,
                                  related_name='candidates')
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    vote_count = models.IntegerField(default=0)

class Vote(models.Model):
    voter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    election = models.ForeignKey(Election, on_delete=models.CASCADE)
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    class Meta:
        unique_together = ('voter', 'election')  # one vote per user per election