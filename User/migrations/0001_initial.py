# Generated by Django 5.0.3 on 2024-03-10 06:31

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('plug', models.CharField(max_length=20)),
                ('AccNumber', models.IntegerField()),
                ('Reflactor', models.CharField(max_length=100)),
                ('Router1', models.CharField(max_length=100)),
                ('Router2', models.CharField(max_length=100)),
                ('Router3', models.CharField(max_length=100)),
                ('notch1', models.CharField(default=None, max_length=10, null=True)),
                ('notch2', models.CharField(default=None, max_length=10, null=True)),
                ('notch3', models.CharField(default=None, max_length=10, null=True)),
                ('key', models.CharField(max_length=10)),
                ('ring', models.CharField(max_length=10)),
                ('specialch', models.CharField(max_length=8)),
                ('user_name', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
