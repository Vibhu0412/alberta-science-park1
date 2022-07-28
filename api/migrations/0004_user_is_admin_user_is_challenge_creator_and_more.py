# Generated by Django 4.0.5 on 2022-07-24 16:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_alter_user_role'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_admin',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='is_challenge_creator',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='is_manager',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='is_solution_seeker',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.ManyToManyField(related_name='role', to='api.userrole'),
        ),
    ]
