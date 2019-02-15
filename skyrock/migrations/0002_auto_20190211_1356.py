# -*- coding: utf-8 -*-
# Generated by Django 1.10.1 on 2019-02-11 13:56
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0001_initial'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Skill',
            new_name='Challenge',
        ),
        migrations.RenameModel(
            old_name='StudentSkill',
            new_name='StudentChallenge',
        ),
        migrations.RemoveField(
            model_name='task',
            name='skills',
        ),
        migrations.AddField(
            model_name='project',
            name='challenges',
            field=models.ManyToManyField(to='skyrock.Challenge'),
        ),
    ]
