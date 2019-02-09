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
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
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
    role = EnumField(
        Role,
        max_length=50,
        default=Role.PARENT)
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
    parent = models.ForeignKey('skyrock.User')
    age = models.IntegerField()
    email = models.EmailField(_('email address'), null=True, unique=True)
    phone = models.IntegerField()
    

class StudentColor(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    color = models.ForeignKey('skyrock.Color')

    description = models.CharField(max_length=200, blank=True)
    user = models.ForeignKey('skyrock.Student')
    progress = models.IntegerField()


class StudentCourse(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    course = models.ForeignKey('skyrock.Pathway')
    description = models.CharField(max_length=200, blank=True)
    user = models.ForeignKey('skyrock.Student')
    progress = models.IntegerField()


class StudentProject(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    project = models.ForeignKey('skyrock.Project')
    user = models.ForeignKey('skyrock.Student')
    progress = models.IntegerField()
    complete = models.BooleanField(default=False)


class StudentTask(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    task = models.ForeignKey('skyrock.task')
    user = models.ForeignKey('skyrock.Student')
    complete = models.BooleanField(default=False)


class StudentSkill(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    skill = models.ForeignKey('skyrock.Skill')
    user = models.ForeignKey('skyrock.Student')
    complete = models.BooleanField(default=False)
    level = models.IntegerField(default=0)


class StudentBadge(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    badge = models.ForeignKey('skyrock.Badge')
    user = models.ForeignKey('skyrock.Student')
    level = models.IntegerField(default=0)


class Color(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    description = models.CharField(max_length=200, blank=True)


class Pathway(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    description = models.CharField(max_length=200, blank=True)
    colors = models.ManyToManyField('skyrock.Color')
    projects = models.ManyToManyField('skyrock.Project')


class Project(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    description = models.CharField(max_length=200, blank=True)
    tasks = models.ManyToManyField('skyrock.Task')


class Task(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    description = models.CharField(max_length=200, blank=True)
    skills = models.ManyToManyField('skyrock.Skill')


class Skill(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    description = models.CharField(max_length=200, blank=True)


class Badge(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    description = models.CharField(max_length=200, blank=True)

