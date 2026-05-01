
# Create your models here.
from django.contrib.auth.models import AbstractUser 
from django.db import models
                                                                                                            
class CustomUser(AbstractUser):
      ROLE_CHOICES = [                                                                                      
          ('voter',       'Voter'),                                                                       
          ('admin',       'Admin'),
          ('soc_analyst', 'SOC Analyst'),
      ]
      role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='voter')

      def __str__(self):
          return f"{self.username} ({self.role})"