# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2019-08-25 07:44
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0017_auto_20190822_1148'),
    ]

    operations = [
        migrations.AddField(
            model_name='badge',
            name='club_relation',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AlterField(
            model_name='student',
            name='client',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='student', to='skyrock.Client'),
        ),
    ]
