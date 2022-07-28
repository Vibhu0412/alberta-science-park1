from django.db import models
from api.models import User


# Create your models here.
class Industry(models.Model):

    INDUSTRY_CHOICES = (
        ('Oil & Gas', 'Oil & Gas'),
        ('Electricity', 'Electricity'),
        ('Agriculture', 'Agriculture'),
        ('Information Technology', 'Information Technology'),
        ('Finance', 'Finance'),
    )
    # id = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, primary_key=True)
    name = models.CharField(max_length=50, choices=INDUSTRY_CHOICES)

    class META:
        verbose_name = 'Challenge Industry'
        verbose_name_plural = 'Challenge Industries'

    def __str__(self):
        return f'{self.name}'


class ChallengeStatement(models.Model):
    STATUS = (
        ('New', 'New'),
        ('Completed', 'Completed'),
        ('Cancelled', 'Cancelled'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    challenge_title = models.CharField(max_length=100)
    challenge_description = models.CharField(max_length=450, blank=True)
    challenge_location = models.CharField(max_length=50, default="Canada")
    industry = models.ManyToManyField(Industry, related_name="industry")

    is_active = models.BooleanField(default=True)
    status = models.CharField(max_length=10, choices=STATUS, default='New')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Challenge Statement'
        verbose_name_plural = 'Challenge Statement'

    def __str__(self):
        return f"{self.challenge_title[0:20]} ..."


