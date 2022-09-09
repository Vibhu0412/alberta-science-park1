# Generated by Django 4.0.5 on 2022-08-25 11:48

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_personalinformation_personal_skills_and_more'),
        ('challenge_creator', '0003_challengestatement_skills'),
    ]

    operations = [
        migrations.AddField(
            model_name='challengestatement',
            name='company_name',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='api.businessinformation'),
        ),
        migrations.AlterField(
            model_name='challengestatement',
            name='skills',
            field=models.CharField(blank=True, max_length=2000, null=True),
        ),
    ]