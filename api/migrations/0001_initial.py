# Generated by Django 4.0.5 on 2022-09-20 05:57

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('uid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True, verbose_name='Public Identifier')),
                ('email', models.EmailField(max_length=50, unique=True)),
                ('username', models.CharField(max_length=20, unique=True)),
                ('can_invite_others', models.BooleanField(default=True)),
                ('is_fresh_login', models.BooleanField(default=True)),
                ('date_joined', models.DateTimeField(auto_now_add=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('is_challenge_creator', models.BooleanField(default=False)),
                ('is_solution_provider', models.BooleanField(default=False)),
                ('is_manager', models.BooleanField(default=False)),
                ('is_staff', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='UserRole',
            fields=[
                ('id', models.PositiveSmallIntegerField(choices=[(1, 'Admin'), (2, 'Challenge Creator'), (3, 'Solution Provider'), (4, 'Manager'), (5, 'God Level Admin')], primary_key=True, serialize=False)),
            ],
        ),
        migrations.CreateModel(
            name='ProfessionalExperience',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('industry', models.CharField(blank=True, max_length=40, null=True)),
                ('company_name', models.CharField(blank=True, max_length=40, null=True)),
                ('designation_title', models.CharField(blank=True, max_length=40, null=True)),
                ('employment_type', models.CharField(blank=True, choices=[('Full-time', 'Full-time'), ('Part-time', 'Part-time'), ('Self-Employed', 'Self-Employed'), ('Freelance', 'Freelance'), ('Internship', 'Internship'), ('Trainee', 'Trainee')], max_length=60, null=True)),
                ('location', models.CharField(blank=True, max_length=40, null=True)),
                ('start_date', models.DateField(blank=True, null=True)),
                ('end_date', models.DateField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='professional_experience', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PersonalInformation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(blank=True, max_length=30, null=True)),
                ('last_name', models.CharField(blank=True, max_length=50, null=True)),
                ('personal_email', models.EmailField(blank=True, max_length=254, null=True, unique=True)),
                ('personal_skills', models.CharField(blank=True, max_length=2000, null=True)),
                ('job_title', models.CharField(blank=True, max_length=400, null=True)),
                ('headline', models.CharField(blank=True, max_length=400, null=True)),
                ('bio', models.CharField(blank=True, max_length=400, null=True)),
                ('office_phone', models.CharField(blank=True, max_length=13, null=True)),
                ('personal_phone', models.CharField(blank=True, max_length=13, null=True)),
                ('address_line_1', models.CharField(blank=True, max_length=100, null=True)),
                ('address_line_2', models.CharField(blank=True, max_length=100, null=True)),
                ('city', models.CharField(blank=True, max_length=20, null=True)),
                ('state', models.CharField(blank=True, max_length=20, null=True)),
                ('country', models.CharField(blank=True, max_length=20, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='personal', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Personal Information',
                'verbose_name_plural': 'Personal Information',
            },
        ),
        migrations.CreateModel(
            name='PersonalEducation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('school', models.CharField(blank=True, max_length=40, null=True)),
                ('degree', models.CharField(blank=True, max_length=40, null=True)),
                ('field_of_study', models.CharField(blank=True, max_length=40, null=True)),
                ('start_date', models.DateField(blank=True, null=True)),
                ('end_date', models.DateField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='personal_education', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PersonalDocumentUpload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('upload_documents', models.FileField(upload_to='documents/')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='upload_documents', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PersonalCertificates',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('certificate_name', models.CharField(blank=True, max_length=200, null=True)),
                ('issue_authority', models.CharField(blank=True, max_length=200, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='personal_certificates', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='LanguagesSpoken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('language_name', models.CharField(blank=True, max_length=40, null=True)),
                ('language_proficiency', models.CharField(blank=True, choices=[('No Proficiency', 'No Proficiency'), ('Elementary Proficiency', 'Elementary Proficiency'), ('Limited Working Proficiency', 'Limited Working Proficiency'), ('Professional Working Proficiency', 'Professional Working Proficiency'), ('Native / Bilingual Proficiency', 'Native / Bilingual Proficiency')], max_length=60, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='languages_spoken', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='InvitedUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('company_name', models.CharField(blank=True, max_length=50, null=True)),
                ('invite_limit', models.IntegerField(default=2)),
                ('can_invite_others', models.BooleanField(default=True)),
                ('is_accepted', models.BooleanField(default=False)),
                ('is_decline', models.BooleanField(default=False)),
                ('is_registered', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('invited_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='invitedby', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='HonorsAndAwards',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(blank=True, max_length=200, null=True)),
                ('issuer', models.CharField(blank=True, max_length=200, null=True)),
                ('description', models.CharField(blank=True, max_length=200, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='honor_and_awards', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='BusinessLabEquipments',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hardware_software', models.CharField(blank=True, max_length=400, null=True)),
                ('title_of_equipment', models.CharField(blank=True, max_length=400, null=True)),
                ('equipment_description', models.CharField(blank=True, max_length=400, null=True)),
                ('usability', models.CharField(blank=True, max_length=400, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='lab_equipments', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='BusinessInformation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('userid', models.IntegerField(blank=True, null=True)),
                ('company_name', models.CharField(blank=True, max_length=50, null=True)),
                ('company_website', models.URLField(blank=True, null=True)),
                ('company_description', models.TextField(blank=True, null=True)),
                ('company_email', models.EmailField(blank=True, max_length=50, null=True, unique=True)),
                ('company_phone', models.CharField(blank=True, max_length=13, null=True)),
                ('company_address_line_1', models.CharField(blank=True, max_length=100, null=True)),
                ('company_address_line_2', models.CharField(blank=True, max_length=100, null=True)),
                ('company_classification', models.CharField(choices=[('S11', 'Agriculture, Forestry, Fishing and Hunting'), ('S21', 'Mining, Quarrying, and Oil and Gas Extraction'), ('S22', 'Utilities'), ('S23', 'Construction'), ('S31', 'Manufacturing')], default='S23', max_length=3)),
                ('company_city', models.CharField(blank=True, max_length=20, null=True)),
                ('company_state', models.CharField(blank=True, max_length=20, null=True)),
                ('company_country', models.CharField(blank=True, max_length=20, null=True)),
                ('invite_through_company', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='Business', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Business Information',
                'verbose_name_plural': 'Business Information',
            },
        ),
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.ManyToManyField(related_name='role', to='api.userrole'),
        ),
    ]
