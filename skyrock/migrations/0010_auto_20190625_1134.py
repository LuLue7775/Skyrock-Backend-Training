# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2019-06-25 11:34
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0009_auto_20190625_1118'),
    ]

    operations = [
        migrations.AlterField(
            model_name='booking',
            name='date',
            field=models.DateTimeField(),
        ),
    ]
