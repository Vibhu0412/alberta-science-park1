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

    can_invite_others = models.BooleanField(default=True)
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

    # @property
    # def full_name(self):
    #     return f'{self.Personal.first_name} {self.Personal.last_name}'

    class META:
        verbose_name = 'user'
        verbose_name_plural = 'users'


class PersonalInformation(models.Model):
    user = models.OneToOneField(User, related_name="personal", on_delete=models.CASCADE)
    first_name = models.CharField(max_length=30, blank=True, null=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    personal_email = models.EmailField(unique=True, blank=True, null=True)
    personal_skills = models.CharField(max_length=2000, blank=True, null=True)

    job_title = models.CharField(max_length=400, blank=True, null=True)
    headline = models.CharField(max_length=400, blank=True, null=True)
    bio = models.CharField(max_length=400, blank=True, null=True)

    office_phone = models.CharField(max_length=13, blank=True, null=True)
    personal_phone = models.CharField(max_length=13, blank=True, null=True)
    address_line_1 = models.CharField(max_length=100, blank=True, null=True)
    address_line_2 = models.CharField(max_length=100, blank=True, null=True)
    # profile_picture = models.ImageField(upload_to='userprofile', blank=True)
    city = models.CharField(max_length=20, blank=True, null=True)
    state = models.CharField(max_length=20, blank=True, null=True)
    country = models.CharField(max_length=20, blank=True, null=True)

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Personal Information'
        verbose_name_plural = 'Personal Information'

    def __str__(self):
        return self.user.email

    def full_address(self):
        return f'{self.address_line_1} {self.address_line_2}'

    def full_name(self):
        return f'{self.first_name} {self.last_name}'


class PersonalDocumentUpload(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='upload_documents',blank=True, null=True)
    # upload_documents = models.FileField(upload_to='upload/')
    upload_documents = models.FileField(upload_to='documents/')

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.user)

class PersonalEducation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='personal_education')
    school = models.CharField(max_length=40, blank=True, null=True)
    degree = models.CharField(max_length=40, blank=True, null=True)
    field_of_study = models.CharField(max_length=40, blank=True, null=True)
    start_date = models.DateField(blank=True, null=True)
    end_date = models.DateField(blank=True, null=True)

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.user)

class ProfessionalExperience(models.Model):
    EMPLOYMENT_TYPE_CHOICES = (
        ('Full-time', 'Full-time'),
        ('Part-time', 'Part-time'),
        ('Self-Employed','Self-Employed'),
        ('Freelance','Freelance'),
        ('Internship','Internship'),
        ('Trainee','Trainee'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='professional_experience')
    industry = models.CharField(max_length=40, blank=True, null=True)
    # profile_headline = models.CharField(max_length=40, blank=True, null=True)
    company_name = models.CharField(max_length=40, blank=True, null=True)
    designation_title = models.CharField(max_length=40, blank=True, null=True)

    employment_type = models.CharField(choices=EMPLOYMENT_TYPE_CHOICES,max_length=60, blank=True, null=True)
    location = models.CharField(max_length=40, blank=True, null=True)
    start_date = models.DateField(blank=True, null=True)
    end_date = models.DateField(blank=True, null=True)

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.user)

class LanguagesSpoken(models.Model):
    LANGUAGE_PROFICIENCY = (
        ('No Proficiency', 'No Proficiency'),
        ('Elementary Proficiency', 'Elementary Proficiency'),
        ('Limited Working Proficiency','Limited Working Proficiency'),
        ('Professional Working Proficiency','Professional Working Proficiency'),
        ('Native / Bilingual Proficiency','Native / Bilingual Proficiency'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='languages_spoken')
    language_name = models.CharField(max_length=40, blank=True, null=True)
    language_proficiency = models.CharField(choices=LANGUAGE_PROFICIENCY,max_length=60, blank=True, null=True)

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(auto_now=True)
    def __str__(self):
        return str(self.user)

class PersonalCertificates(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='personal_certificates')
    certificate_name = models.CharField(max_length=200, blank=True, null = True)
    issue_authority = models.CharField(max_length=200, blank=True, null = True)

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(auto_now=True)
    def __str__(self):
        return str(self.user)

class HonorsAndAwards(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='honor_and_awards')
    title = models.CharField(max_length=200, blank=True, null=True)
    issuer = models.CharField(max_length=200, blank=True, null=True)
    description = models.CharField(max_length=200, blank=True, null=True)

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.user)


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
    userid = models.IntegerField(blank=True, null=True)
    user = models.ForeignKey(User, related_name="Business", on_delete=models.CASCADE)

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

    invite_through_company = models.BooleanField(default=False)

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Business Information'
        verbose_name_plural = 'Business Information'

    def __str__(self):
        return self.user.email

    def full_address(self):
        return f'{self.company_address_line_1} {self.company_address_line_2}'

class BusinessLabEquipments(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="lab_equipments")
    hardware_software = models.CharField(max_length=400, blank=True, null=True)
    title_of_equipment = models.CharField(max_length=400, blank=True, null=True)
    equipment_description = models.CharField(max_length=400, blank=True, null=True)
    usability = models.CharField(max_length=400, blank=True, null=True)

    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(auto_now=True)


class InvitedUser(models.Model):
    email = models.EmailField()
    invited_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="invitedby")
    company_name = models.CharField(max_length=50, blank=True, null=True)
    invite_limit = models.IntegerField(default=2)
    can_invite_others = models.BooleanField(default=True)

    is_accepted= models.BooleanField(default=False)
    is_decline = models.BooleanField(default=False)

    is_registered = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    modified_at = models.DateTimeField(auto_now=True)

    class META:
        verbose_name = 'Invited User'
        verbose_name_plural = 'Invited Users'

    def __str__(self):
        return self.email

    def fetch_invited_by(self):
        return self.invited_by.email
