# -*- coding: utf-8 -*-
# Generated by Django 1.10.1 on 2019-03-25 09:07
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0010_auto_20190325_0734'),
    ]

    operations = [
        migrations.AlterField(
            model_name='student',
            name='pathways',
            field=models.ManyToManyField(blank=True, to='skyrock.Pathway'),
        ),
    ]
