# -*- coding: utf-8 -*-
# Generated by Django 1.10.1 on 2019-02-15 11:08
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0003_auto_20190211_1426'),
    ]

    operations = [
        migrations.CreateModel(
            name='Parent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('updated', models.DateTimeField(auto_now=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('email', models.EmailField(max_length=254, null=True, unique=True, verbose_name='email address')),
                ('phone', models.IntegerField()),
                ('cost', models.IntegerField()),
                ('payment', models.CharField(blank=True, max_length=200)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='StudentPathway',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('updated', models.DateTimeField(auto_now=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('identifier', models.UUIDField(db_index=True, default=uuid.uuid4, unique=True)),
                ('complete', models.BooleanField(default=False)),
                ('pathway', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='skyrock.Pathway')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.RemoveField(
            model_name='studentcourse',
            name='course',
        ),
        migrations.RemoveField(
            model_name='studentcourse',
            name='user',
        ),
        migrations.RemoveField(
            model_name='user',
            name='role',
        ),
        migrations.AddField(
            model_name='student',
            name='current_teacher',
            field=models.ForeignKey(blank=True, default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='student',
            name='hours',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='challenge',
            name='tags',
            field=models.ManyToManyField(blank=True, to='skyrock.Tag'),
        ),
        migrations.AlterField(
            model_name='student',
            name='parent',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='skyrock.Parent'),
        ),
        migrations.DeleteModel(
            name='StudentCourse',
        ),
        migrations.AddField(
            model_name='student',
            name='pathways',
            field=models.ManyToManyField(blank=True, to='skyrock.StudentPathway'),
        ),
    ]
