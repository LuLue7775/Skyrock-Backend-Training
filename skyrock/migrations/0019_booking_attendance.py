# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2019-08-26 03:16
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0018_auto_20190825_0744'),
    ]

    operations = [
        migrations.AddField(
            model_name='booking',
            name='attendance',
            field=models.BooleanField(default=True),
        ),
    ]
