# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2019-08-26 10:08
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0020_auto_20190826_0318'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='client',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user', to='skyrock.Client'),
        ),
    ]