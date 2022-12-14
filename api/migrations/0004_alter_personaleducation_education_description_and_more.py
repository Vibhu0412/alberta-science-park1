# Generated by Django 4.0.5 on 2022-09-20 13:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_personaleducation_education_description'),
    ]

    operations = [
        migrations.AlterField(
            model_name='personaleducation',
            name='education_description',
            field=models.CharField(blank=True, max_length=400, null=True),
        ),
        migrations.AlterField(
            model_name='personalinformation',
            name='city',
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
        migrations.AlterField(
            model_name='personalinformation',
            name='country',
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
        migrations.AlterField(
            model_name='personalinformation',
            name='state',
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
        migrations.AlterField(
            model_name='professionalexperience',
            name='experience_description',
            field=models.CharField(blank=True, max_length=400, null=True),
        ),
    ]
