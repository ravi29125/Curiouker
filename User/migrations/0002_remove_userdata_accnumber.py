# Generated by Django 5.0.3 on 2024-03-10 06:54

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('User', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userdata',
            name='AccNumber',
        ),
    ]
