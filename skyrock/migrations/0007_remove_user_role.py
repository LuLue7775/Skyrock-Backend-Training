# -*- coding: utf-8 -*-
# Generated by Django 1.11.3 on 2019-03-25 05:16
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0006_auto_20190325_0513'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='role',
        ),
    ]
