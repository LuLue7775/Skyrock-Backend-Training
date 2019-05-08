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
    age = models.IntegerField()
    email = models.EmailField(_('email address'), null=True)
    phone = models.CharField(max_length=50, db_index=True, blank=True)
    hours_remaining = models.IntegerField()
    hours_spent = models.IntegerField()
    parent = models.ForeignKey('skyrock.Parent')
    notes = models.CharField(max_length=200, db_index=True, blank=True)
    badges = models.ManyToManyField('skyrock.Badge', blank=True)


class Parent(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    email = models.EmailField(_('email address'), null=True)
    phone = models.CharField(max_length=50, db_index=True, blank=True)
    payment_status = models.CharField(max_length=200, blank=True)
    location = EnumField(
                Location, 
                max_length=50,
                default=Location.NONE)

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

class Program(DateModel):
    student = models.ForeignKey('skyrock.Student')
    pathway = models.ForeignKey('skyrock.Pathway', blank=True)
    hours = models.IntegerField()
    location = EnumField(
                Location, 
                max_length=50,
                default=Location.NONE)
    current = models.BooleanField(default=True)
    teacher = models.CharField(max_length=50, db_index=True, blank=True)


class Pathway(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    description = models.CharField(max_length=200, blank=True)
    hours = models.IntegerField()


class Sale(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    location = EnumField(
                Location, 
                max_length=50)
    amount = models.IntegerField()
    parent = models.ForeignKey('skyrock.Parent')
    description = models.CharField(max_length=200, blank=True)
    pathway = models.ForeignKey('skyrock.Pathway')


class Booking(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    location = EnumField(
                Location, 
                max_length=50,
                default=Location.NONE)
    student = models.ForeignKey('skyrock.Student')
    date = models.DateField()
    class_type = models.CharField(max_length=100)
    teacher = models.CharField(max_length=100)


class Badge(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    description = models.CharField(max_length=200, blank=True)
