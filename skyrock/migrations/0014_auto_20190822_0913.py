# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2019-08-22 09:13
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0013_auto_20190822_0909'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='student',
            name='age',
        ),
        migrations.AddField(
            model_name='student',
            name='birth_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
