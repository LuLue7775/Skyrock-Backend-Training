# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2019-08-22 11:48
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0016_auto_20190822_0933'),
    ]

    operations = [
        migrations.AlterField(
            model_name='club',
            name='student',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='clubs', to='skyrock.Student'),
        ),
    ]
