from django.db import models
from api.models import User, BusinessInformation
from django.utils import timezone

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

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(default=timezone.now)

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

    POST_TYPE=(
        ('Draft','Draft'),
        ('Active', 'Active'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='personalinfo')
    challenge_title = models.CharField(max_length=100)
    challenge_description = models.CharField(max_length=450, blank=True)
    challenge_location = models.CharField(max_length=50, default="Canada")
    industry = models.ManyToManyField(Industry, related_name="industry")
    skills = models.CharField(max_length=2000, blank=True, null=True)
    company_name = models.ForeignKey(BusinessInformation, on_delete=models.CASCADE, null=True, blank=True)
    status_type = models.CharField(max_length=10, choices=STATUS, default='New')
    post_type = models.CharField(max_length=10, choices=POST_TYPE, default='Active')

    is_active = models.BooleanField(default=True)
    is_archieve = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    ## New ##


    class Meta:
        verbose_name = 'Challenge Statement'
        verbose_name_plural = 'Challenge Statement'

    def full_name(self):
        return f'{self.user.Personal.first_name} {self.user.Personal.last_name}'
        # return f'{self.first_name} {self.last_name}'


    def __str__(self):
        return f"{self.challenge_title[0:20]} ..."

#### New ###
class Comment(models.Model):
    """User comment"""
    post = models.ForeignKey(ChallengeStatement, related_name='comments', on_delete=models.CASCADE)
    commented_by = models.ForeignKey(User, on_delete=models.CASCADE)
    company_name = models.ForeignKey(BusinessInformation, on_delete=models.CASCADE, null=True, blank=True)
    user_comment = models.CharField(max_length=500)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.user_comment[:20]
