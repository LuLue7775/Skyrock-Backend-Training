# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2019-06-24 13:25
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0005_auto_20190624_1320'),
    ]

    operations = [
        migrations.RenameField(
            model_name='student',
            old_name='pathway',
            new_name='current_pathway',
        ),
    ]
