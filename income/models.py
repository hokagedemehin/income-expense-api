from django.db import models

# Create your models here.

from django.db import models
from  authentication.models import *
from django.utils import timezone

# Create your models here.

class Income(models.Model):
    SOURCE_OPTIONS = [
        ('SALARY', 'SALARY'),
        ('BUSINESS', 'BUSINESS'),
        ('SIDE-HUSTLE', 'SIDE-HUSTLE'),
        ('GIFT', 'GIFT'),
        ('SALES', 'SALES'),
        ('OTHERS', 'OTHERS'),
    ]

    source = models.CharField(choices=SOURCE_OPTIONS,max_length=100, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    description = models.TextField(null=True, blank=True)
    owner = models.ForeignKey(to=User, on_delete=models.CASCADE)
    date = models.DateField(null=False, blank=False, default=timezone.now)
    
    class Meta:
        ordering = ['-date']

    def __str__(self):
        return str(self.owner.username) +  "'s Income"
    