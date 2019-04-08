import uuid
import datetime
import uuid
import re
import requests
import json
import os

from enumfields import EnumField
from skyrock.enums import *

from django.db import models
from django.utils.timezone import utc
from django.template import Template
from django.template import Context
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.postgres.fields import JSONField, ArrayField
from django.utils.translation import ugettext_lazy as _
from django.utils.timezone import (
    utc, now
)
from django.db import models


class DateModel(models.Model):
    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True

    def __str__(self):
        return str(self.created)


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        print("model")
        print(extra_fields)
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        print(extra_fields)

        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class AbstractUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=30, blank=True)
    email = models.EmailField(_('email address'), null=True, unique=True)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=now)
    objects = UserManager()
    all_objects = BaseUserManager()
    role = EnumField(
                Role, 
                max_length=50,
                default=Role.STUDENT)

    USERNAME_FIELD = 'email'

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = True

    def __str__(self):
        return self.email

    def get_full_name(self):
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name


class User(AbstractUser, DateModel):
    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'


class Student(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    parent = models.ForeignKey('skyrock.Parent')
    age = models.IntegerField()
    email = models.EmailField(_('email address'), null=True)
    phone = models.CharField(max_length=50, db_index=True, blank=True)
    hours = models.IntegerField()
    current_teacher = models.CharField(max_length=50, db_index=True, blank=True)
    current_pathway = models.CharField(max_length=50, db_index=True, blank=True)
    pathways = models.ManyToManyField('skyrock.Pathway', blank=True)


class Parent(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    email = models.EmailField(_('email address'), null=True)
    phone = models.CharField(max_length=50, db_index=True, blank=True)
    cost = models.IntegerField()
    payment = models.CharField(max_length=200, blank=True)


class Attendance(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    student = models.ForeignKey('skyrock.Student')
    pathway = models.CharField(max_length=50, db_index=True, blank=True)
    status = EnumField(
                Attendance_status, 
                max_length=50,
                default=Attendance_status.PRESENT)
    date =  models.DateTimeField(default=now)

# class StudentColor(DateModel):
#     identifier = models.UUIDField(unique=True, db_index=True,
#         default=uuid.uuid4)
#     color = models.ForeignKey('skyrock.Color')
#     description = models.CharField(max_length=200, blank=True)
#     user = models.ForeignKey('skyrock.Student')
#     progress = models.IntegerField()


class StudentPathway(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    pathway = models.ForeignKey('skyrock.Pathway')
    complete = models.BooleanField(default=False)


# class StudentProject(DateModel):
#     identifier = models.UUIDField(unique=True, db_index=True,
#         default=uuid.uuid4)
#     project = models.ForeignKey('skyrock.Project')
#     user = models.ForeignKey('skyrock.Student')
#     progress = models.IntegerField()
#     complete = models.BooleanField(default=False)


# class StudentTask(DateModel):
#     identifier = models.UUIDField(unique=True, db_index=True,
#         default=uuid.uuid4)
#     task = models.ForeignKey('skyrock.task')
#     user = models.ForeignKey('skyrock.Student')
#     complete = models.BooleanField(default=False)


# class StudentChallenge(DateModel):
#     identifier = models.UUIDField(unique=True, db_index=True,
#         default=uuid.uuid4)
#     skill = models.ForeignKey('skyrock.Challenge')
#     user = models.ForeignKey('skyrock.Student')
#     complete = models.BooleanField(default=False)
#     level = models.IntegerField(default=0)


# class StudentBadge(DateModel):
#     identifier = models.UUIDField(unique=True, db_index=True,
#         default=uuid.uuid4)
#     badge = models.ForeignKey('skyrock.Badge')
#     user = models.ForeignKey('skyrock.Student')
#     level = models.IntegerField(default=0)


# class Color(DateModel):
#     identifier = models.UUIDField(unique=True, db_index=True,
#         default=uuid.uuid4)
#     name = models.CharField(max_length=50, db_index=True, blank=True)
#     description = models.CharField(max_length=200, blank=True)


class Pathway(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    description = models.CharField(max_length=200, blank=True)
    hours = models.IntegerField()

    # colors = models.ManyToManyField('skyrock.Color')
    # projects = models.ManyToManyField('skyrock.Project')


# class Project(DateModel):
#     identifier = models.UUIDField(unique=True, db_index=True,
#         default=uuid.uuid4)
#     name = models.CharField(max_length=50, db_index=True, blank=True)
#     description = models.CharField(max_length=200, blank=True)
#     tasks = models.ManyToManyField('skyrock.Task')
#     challenges = models.ManyToManyField('skyrock.Challenge')


# class Task(DateModel):
#     identifier = models.UUIDField(unique=True, db_index=True,
#         default=uuid.uuid4)
#     name = models.CharField(max_length=50, db_index=True, blank=True)
#     description = models.CharField(max_length=200, blank=True)
#     tags = models.ManyToManyField('skyrock.Tag', blank=True, default=None)


# class Challenge(DateModel):
#     identifier = models.UUIDField(unique=True, db_index=True,
#         default=uuid.uuid4)
#     name = models.CharField(max_length=50, db_index=True, blank=True)
#     description = models.CharField(max_length=200, blank=True)
#     tags = models.ManyToManyField('skyrock.Tag', blank=True)


# class Tag(DateModel):
#     name = models.CharField(max_length=50, db_index=True, unique=True)


# class Badge(DateModel):
#     identifier = models.UUIDField(unique=True, db_index=True,
#         default=uuid.uuid4)
#     name = models.CharField(max_length=50, db_index=True, blank=True)
#     description = models.CharField(max_length=200, blank=True)
#     tag = models.ForeignKey('skyrock.Tag')


class Sale(DateModel):
    location = EnumField(
                Location, 
                max_length=50)
    student = models.ForeignKey('skyrock.Student')
    amount = models.IntegerField()
    description = models.CharField(max_length=200, blank=True)
    pathway = models.ForeignKey('skyrock.Pathway')


class Booking(DateModel):
    location = EnumField(
                Location, 
                max_length=50,
                default=Location.NONE)
    student = models.CharField(max_length=100)
    date = models.DateField()
    code = models.CharField(max_length=50)
    class_type = models.CharField(max_length=100)
    teacher = models.CharField(max_length=100)
    client_email = models.CharField(max_length=100)

