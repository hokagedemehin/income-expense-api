from django.db import models
from  authentication.models import User
from django.utils import timezone

# Create your models here.

class Expense(models.Model):
    CATEGORY_OPTIONS = [
        ('ONLINE_SERVICES', 'ONLINE_SERVICES'),
        ('REGULAR_BILL', 'REGULAR_BILL'),
        ('TRAVEL', 'TRAVEL'),
        ('FOOD', 'FOOD'),
        ('RENT', 'RENT'),
        ('OTHERS', 'OTHERS'),
    ]

    category = models.CharField(choices=CATEGORY_OPTIONS,max_length=100, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    description = models.TextField(null=True, blank=True)
    owner = models.ForeignKey(to=User, on_delete=models.CASCADE)
    date = models.DateField(null=False, blank=False, default=timezone.now)
    
    class Meta:
        ordering = ['-date']

    def __str__(self):
        return str(self.owner.username) + "'s Expense"
    