from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
import uuid
from django.contrib.auth.models import PermissionsMixin
from django.utils import timezone

from .managers import CustomUserManager


# Create your models here.
class UserRole(models.Model):
    """
      The Role entries are managed by the system,
      automatically created via a Django data migration.
    """
    ADMIN = 1
    SOLUTION_SEEKER = 2
    SOLUTION_PROVIDER = 3
    MANAGER = 4
    GOD_ADMIN = 5
    ROLE_CHOICES = (
        (ADMIN, 'Admin'),
        (SOLUTION_SEEKER, 'Challenge Creator'),
        (SOLUTION_PROVIDER, 'Solution Provider'),
        (MANAGER, 'Manager'),
        (GOD_ADMIN, 'God Level Admin'),
    )

    id = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, primary_key=True)

    class META:
        verbose_name = 'User Role'
        verbose_name_plural = 'User Roles'

    def __str__(self):
        return f'{self.id} - {self.get_id_display()}'


class User(AbstractBaseUser):
    uid = models.UUIDField(unique=True, editable=False, default=uuid.uuid4, verbose_name='Public Identifier')
    email = models.EmailField(unique=True, max_length=50)
    username = models.CharField(unique=True, max_length=20)
    role = models.ManyToManyField(UserRole, related_name='role')

    is_fresh_login = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    is_admin = models.BooleanField(default=False)
    is_challenge_creator = models.BooleanField(default=False)
    is_solution_provider = models.BooleanField(default=False)
    is_manager = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        """Does the user have a specific permission?"""
        # Simplest possible answer: Yes, always
        return self.is_staff

    def has_module_perms(self, app_label):
        """Does the user have permissions to view the app `app_label`?"""
        # Simplest possible answer: Yes, always
        return self.is_staff

    class META:
        verbose_name = 'user'
        verbose_name_plural = 'users'


class PersonalInformation(models.Model):
    JUNIOR = 'Junior'
    SENIOR = 'Senior'
    EXPERT = 'Expert'

    EXPERIENCE_LEVEL_CHOICES = (
        (JUNIOR, 'Junior'),
        (SENIOR, 'Senior'),
        (EXPERT, 'Expert'),
    )
    user = models.OneToOneField(User, related_name="Personal", on_delete=models.CASCADE)
    first_name = models.CharField(max_length=30, blank=True, null=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    personal_email = models.EmailField(unique=True, blank=True, null=True)

    office_phone = models.CharField(max_length=13, blank=True, null=True)
    education = models.CharField(max_length=255, blank=True, null=True)
    position = models.CharField(max_length=255, blank=True, null=True)
    languages_spoken = models.CharField(max_length=255, blank=True, null=True)
    experience_level = models.CharField(max_length=7, choices=EXPERIENCE_LEVEL_CHOICES, default='Junior')

    address_line_1 = models.CharField(max_length=100, blank=True, null=True)
    address_line_2 = models.CharField(max_length=100, blank=True, null=True)
    # profile_picture = models.ImageField(upload_to='userprofile', blank=True)
    city = models.CharField(max_length=20, blank=True, null=True)
    state = models.CharField(max_length=20, blank=True, null=True)
    country = models.CharField(max_length=20, blank=True, null=True)

    class Meta:
        verbose_name = 'Personal Information'
        verbose_name_plural = 'Personal Information'

    def __str__(self):
        return self.user.email

    def full_address(self):
        return f'{self.address_line_1} {self.address_line_2}'


class BusinessInformation(models.Model):
    SECTOR_11 = 'S11'
    SECTOR_21 = 'S21'
    SECTOR_22 = 'S22'
    SECTOR_23 = 'S23'
    SECTOR_31 = 'S31'

    NAICS_CLASSIFICATION_CHOICES = (
        (SECTOR_11, 'Agriculture, Forestry, Fishing and Hunting'),
        (SECTOR_21, 'Mining, Quarrying, and Oil and Gas Extraction'),
        (SECTOR_22, 'Utilities'),
        (SECTOR_23, 'Construction'),
        (SECTOR_31, 'Manufacturing'),
    )
    user = models.OneToOneField(User, related_name="Business", on_delete=models.CASCADE)

    company_name = models.CharField(max_length=50, blank=True, null=True)
    company_website = models.URLField(blank=True, null=True)
    company_description = models.TextField(blank=True, null=True)
    company_email = models.EmailField(unique=True, max_length=50, blank=True, null=True)
    company_phone = models.CharField(max_length=13, blank=True, null=True)
    company_address_line_1 = models.CharField(max_length=100, blank=True, null=True)
    company_address_line_2 = models.CharField(max_length=100, blank=True, null=True)
    company_classification = models.CharField(max_length=3, choices=NAICS_CLASSIFICATION_CHOICES, default=SECTOR_23)

    company_city = models.CharField(max_length=20, blank=True, null=True)
    company_state = models.CharField(max_length=20, blank=True, null=True)
    company_country = models.CharField(max_length=20, blank=True, null=True)

    class Meta:
        verbose_name = 'Business Information'
        verbose_name_plural = 'Business Information'

    def __str__(self):
        return self.user.email

    def full_address(self):
        return f'{self.company_address_line_1} {self.company_address_line_2}'

