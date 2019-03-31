# -*- coding: utf-8 -*-
# Generated by Django 1.11.3 on 2019-03-25 05:13
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0005_auto_20190319_0840'),
    ]

    operations = [
        migrations.CreateModel(
            name='Attendance',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('updated', models.DateTimeField(auto_now=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('identifier', models.UUIDField(db_index=True, default=uuid.uuid4, unique=True)),
                ('pathway', models.IntegerField()),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.RemoveField(
            model_name='pathway',
            name='projects',
        ),
        migrations.AddField(
            model_name='student',
            name='current_pathway',
            field=models.CharField(blank=True, db_index=True, max_length=50),
        ),
        migrations.AlterField(
            model_name='student',
            name='current_teacher',
            field=models.CharField(blank=True, db_index=True, max_length=50),
        ),
        migrations.AddField(
            model_name='attendance',
            name='student',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='skyrock.Student'),
        ),
    ]
