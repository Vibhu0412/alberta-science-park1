from django.db import models
from api.models import User


# Create your models here.
class SolutionInformationProfile(models.Model):
    # ENTRY = 'Entry Level'
    # INTERMEDIATE = 'Intermediate'
    # EXPERT = 'Expert'

    EXPERIENCE_LEVEL_CHOICES = (
        ("ENTRY", 'Entry Level'),
        ("INTERMEDIATE", 'Intermediate'),
        ("EXPERT", 'Expert'),
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    solution_user_title = models.CharField(max_length=100)
    solution_user_description = models.CharField(max_length=100)

    skills = models.CharField(max_length=300, blank=True, null=True)
    experience_level = models.CharField(max_length=13, choices=EXPERIENCE_LEVEL_CHOICES, default="ENTRY")
    awards = models.CharField(max_length=300, blank=True, null=True)
    employment_history = models.TextField(blank=True, null=True)

    lab_software = models.TextField(blank=True, null=True)
    lab_hardware = models.TextField(blank=True, null=True)
    languages_spoken = models.CharField(max_length=255, blank=True, null=True)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Profile'
        verbose_name_plural = 'Profile'

    def __str__(self):
        return f"{self.user.username} - {self.solution_user_title}"
