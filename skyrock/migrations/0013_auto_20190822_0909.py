# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2019-08-22 09:09
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0012_auto_20190821_0826'),
    ]

    operations = [
        migrations.RenameField(
            model_name='student',
            old_name='name',
            new_name='first_name',
        ),
        migrations.RemoveField(
            model_name='student',
            name='badges',
        ),
        migrations.RemoveField(
            model_name='student',
            name='current_club',
        ),
        migrations.RemoveField(
            model_name='student',
            name='email',
        ),
        migrations.RemoveField(
            model_name='student',
            name='location',
        ),
        migrations.RemoveField(
            model_name='student',
            name='phone',
        ),
        migrations.AddField(
            model_name='club',
            name='badges',
            field=models.ManyToManyField(blank=True, to='skyrock.Badge'),
        ),
        migrations.AddField(
            model_name='club',
            name='student',
            field=models.ForeignKey(default=10, on_delete=django.db.models.deletion.CASCADE, to='skyrock.Student'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='student',
            name='last_name',
            field=models.CharField(blank=True, db_index=True, max_length=50),
        ),
    ]
