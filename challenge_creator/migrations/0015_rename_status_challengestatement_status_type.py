# Generated by Django 4.0.6 on 2022-09-07 11:53

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('challenge_creator', '0014_challengestatement_is_archieve_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='challengestatement',
            old_name='status',
            new_name='status_type',
        ),
    ]