# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2019-08-21 04:37
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0010_auto_20190625_1134'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Parent',
            new_name='Client',
        ),
        migrations.RenameModel(
            old_name='Pathway',
            new_name='Club',
        ),
        migrations.RenameField(
            model_name='attendance',
            old_name='pathway',
            new_name='club',
        ),
        migrations.RenameField(
            model_name='booking',
            old_name='pathway',
            new_name='club',
        ),
        migrations.RenameField(
            model_name='program',
            old_name='pathway',
            new_name='club',
        ),
        migrations.RenameField(
            model_name='sale',
            old_name='parent',
            new_name='client',
        ),
        migrations.RenameField(
            model_name='sale',
            old_name='pathway',
            new_name='club',
        ),
        migrations.RenameField(
            model_name='student',
            old_name='parent',
            new_name='client',
        ),
        migrations.RenameField(
            model_name='student',
            old_name='current_pathway',
            new_name='current_club',
        ),
    ]
