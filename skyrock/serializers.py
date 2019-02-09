import uuid

from rest_framework import serializers
from django.db import transaction
import json
import uuid

from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from allauth.account.models import EmailAddress
from allauth.account import app_settings
from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from django.db import transaction
from django.contrib.auth import authenticate
from rest_auth.serializers import (
    PasswordChangeSerializer as DefaultPasswordChangeSerializer,
    PasswordResetSerializer as DefaultPasswordResetSerializer,
    PasswordResetConfirmSerializer as DefaultPasswordResetConfirmSerializer
)
from django.utils.translation import ugettext_lazy as _

from config import settings

from skyrock.models import  *
from skyrock.forms import PasswordResetForm
from skyrock.enums import *
from skyrock.fields import TimestampField



class DateSerializer(serializers.ModelSerializer):
    created = serializers.SerializerMethodField()
    updated = serializers.SerializerMethodField()

    @staticmethod
    def get_created(obj):
        return int(obj.created.timestamp() * 1000)

    @staticmethod
    def get_updated(obj):
        return int(obj.updated.timestamp() * 1000)


class UserSerializer(DateSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'created', 'updated',)
        read_only_field = ('created', 'updated',)


class TokenSerializer(serializers.Serializer):
    token = serializers.CharField()
    user = UserSerializer()


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    first_name = serializers.CharField(required=False, allow_blank=True,
        max_length=50, write_only=True)
    last_name = serializers.CharField(required=False, allow_blank=True,
        max_length=50, write_only=True)
    password1 = serializers.CharField(required=True, write_only=True,
        max_length=128, style={'input_type': 'password'})
    password2 = serializers.CharField(required=True, write_only=True,
        max_length=128, style={'input_type': 'password'})

    def validate_email(self, email):
        return get_adapter().clean_email(email)

    def validate_password1(self, password):
        return get_adapter().clean_password(password)

    def validate(self, data):
        email = data.get('email')
        password1 = data.get('password1')
        password2 = data.get('password2')

        if password1 != password2:
            raise serializers.ValidationError(
                {"non_field_errors": [
                    _("The two password fields don't match.")]})

        # Further email address validation related to the company.
        if EmailAddress.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError(
                {"email": [_("A user is already registered "
                             "with this email address.")]})

        return data

    def save(self, request):
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.validated_data
        adapter.save_user(request, user, self)
        setup_user_email(request, user, [])
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(required=True, allow_blank=False)
    password = serializers.CharField(max_length=128,
        style={'input_type': 'password'})

    def _validate_user(self, email, password):
        user = None

        if email and password:
            user = authenticate(email=email, password=password)
        else:
            raise serializers.ValidationError(
                {"non_field_errors": [
                    _('Must include "email" and "password".')
                ]}
            )

        return  user

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        user = self._validate_user(email, password)

        if user:
            if not user.is_active:
                raise serializers.ValidationError(
                    {"non_field_errors": [_('User account is disabled.')]})
        else:
            raise serializers.ValidationError(
                {"non_field_errors": [
                    _('Unable to log in with provided credentials.')
                ]})

        # If required, is the email verified?
        if 'rest_auth.registration' in settings.INSTALLED_APPS:
            if (app_settings.EMAIL_VERIFICATION
                    == app_settings.EmailVerificationMethod.MANDATORY):
                email_address = user.emailaddress_set.get(email=user.email)
                if not email_address.verified:
                    raise serializers.ValidationError(
                        {"user": [_('Email is not verified.')]})

        attrs['user'] = user
        return attrs


class LogoutSerializer(serializers.Serializer):
    pass


class PasswordChangeSerializer(DefaultPasswordChangeSerializer):
    """
    Override the default serializer in order to mask the password fields.
    """
    old_password = serializers.CharField(
        max_length=128, style={'input_type': 'password'})
    new_password1 = serializers.CharField(
        max_length=128, style={'input_type': 'password'})
    new_password2 = serializers.CharField(
        max_length=128, style={'input_type': 'password'})


class PasswordResetSerializer(DefaultPasswordResetSerializer):
    password_reset_form_class = PasswordResetForm


class PasswordResetConfirmSerializer(DefaultPasswordResetConfirmSerializer):
    """
    Override the default serializer in order to mask the password fields.
    """
    new_password1 = serializers.CharField(
        max_length=128, style={'input_type': 'password'})
    new_password2 = serializers.CharField(
        max_length=128, style={'input_type': 'password'})


class ResendVerifyEmailSerializer(serializers.Serializer):
    email = serializers.CharField(required=True)


class VerifyEmailSerializer(serializers.Serializer):
    key = serializers.CharField(required=True)


class ColorSerializer(serializers.ModelSerializer):
    identifier = serializers.UUIDField(read_only=True)
    class Meta:
        model = Color
        fields = (
            'identifier',
            'name',
            'description'
        )

    def delete(self):
        self.instance.delete()


class SkillSerializer(serializers.ModelSerializer):
    identifier = serializers.UUIDField(read_only=True)
    class Meta:
        model = Skill
        fields = (
            'identifier',
            'name',
            'description'
        )

    def delete(self):
        self.instance.delete()


class TaskSerializer(serializers.ModelSerializer):
    identifier = serializers.UUIDField(read_only=True)
    skills = SkillSerializer(many=True)
    class Meta:
        model = Task
        fields = (
            'identifier',
            'name',
            'description',
            'skills'
        )

    def delete(self):
        self.instance.delete()


class ProjectSerializer(serializers.ModelSerializer):
    identifier = serializers.UUIDField(read_only=True)
    tasks = TaskSerializer(many=True)
    class Meta:
        model = Project
        fields = (
            'identifier',
            'name',
            'description',
            'tasks'
        )
    def delete(self):
        self.instance.delete()


class PathwaySerializer(serializers.ModelSerializer):
    identifier = serializers.UUIDField(read_only=True)
    colors = ColorSerializer(many=True)
    projects = ProjectSerializer(many=True)

    class Meta:
        model = Pathway
        fields = (
            'identifier',
            'name',
            'description',
            'colors',
            'projects'
        )

    def delete(self):
        self.instance.delete()


class BadgeSerializer(serializers.ModelSerializer):
    identifier = serializers.UUIDField(read_only=True)
    class Meta:
        model = Badge
        fields = (
            'identifier',
            'name',
            'description'
        )

    def delete(self):
        self.instance.delete()
        

class CreateColorSerializer(ColorSerializer):
    name = serializers.CharField(required=True)
    description = serializers.CharField(required=True)

    class Meta:
        model = ColorSerializer.Meta.model
        fields = ColorSerializer.Meta.fields
        read_only_fields = (
            'identifier',
        )


class CreatePathwaySerializer(PathwaySerializer):
    name = serializers.CharField(required=True)
    description = serializers.CharField(required=True)
    colors = serializers.ListField(required=True)
    projects = serializers.ListField(required=True)

    class Meta:
        model = PathwaySerializer.Meta.model
        fields = (
            'identifier',
            'name',
            'description',
            'colors',
            'projects',
        )
        read_only_fields = (
            'identifier',
        )

    def validate(self, validated_data):
        validated_data['user'] = self.context['request'].user
        # validated_data['color'] = self.validated_data.get('color')
        return validated_data

    def create(self, validated_data):
        colors = validated_data.get('colors')
        projects = validated_data.get('projects')

        pathway = Pathway.objects.create(
                name=validated_data['name'],
                description=validated_data['description'],
                )

        for item in colors:
            try:
                color = Color.objects.get(identifier=item)
            except Color.DoesNotExist:
                raise serializers.ValidationError(
                    {"color": ["The color does not exist."]})
            pathway.colors.add(color)

        for item in projects:    
            try:
                project = Project.objects.get(identifier=item)
            except Project.DoesNotExist:
                raise serializers.ValidationError(
                    {"project": ["The project does not exist."]})
            pathway.projects.add(project)

        return pathway

        
class CreateProjectSerializer(ProjectSerializer):
    name = serializers.CharField(required=True)
    description = serializers.CharField(required=True)
    tasks = serializers.ListField(required=True)

    class Meta:
        model = ProjectSerializer.Meta.model
        fields = (
            'identifier',
            'name',
            'description',
            'tasks',
        )
        read_only_fields = (
            'identifier',
        )

    def validate(self, validated_data):
        return validated_data

    def create(self, validated_data):
        tasks = validated_data.get('tasks')

        project = Project.objects.create(
                name=validated_data['name'],
                description=validated_data['description'],
                )

        for item in tasks:
            try:
                task = Task.objects.get(identifier=item)
            except Task.DoesNotExist:
                raise serializers.ValidationError(
                    {"tasks": ["The task does not exist."]})
            project.tasks.add(task)

        return project


class CreateTaskSerializer(TaskSerializer):
    name = serializers.CharField(required=True)
    description = serializers.CharField(required=True)
    skills = serializers.ListField(required=True)

    class Meta:
        model = TaskSerializer.Meta.model
        fields = (
            'identifier',
            'name',
            'description',
            'skills',
        )
        read_only_fields = (
            'identifier',
        )

    def validate(self, validated_data):
        return validated_data

    def create(self, validated_data):
        skills = validated_data.get('skills')

        task = Task.objects.create(
                name=validated_data['name'],
                description=validated_data['description'],
                )

        for item in skills:
            try:
                skill = Skill.objects.get(identifier=item)
                print(skill)
            except Skill.DoesNotExist:
                raise serializers.ValidationError(
                    {"skill": ["The skill does not exist."]})
            task.skills.add(skill)

        return task


class CreateSkillSerializer(SkillSerializer):
    name = serializers.CharField(required=False)
    description = serializers.CharField(required=False)

    class Meta:
        model = SkillSerializer.Meta.model
        fields = SkillSerializer.Meta.fields
        read_only_fields = (
            'identifier',
        )


class CreateBadgeSerializer(BadgeSerializer):
    name = serializers.CharField(required=False)
    description = serializers.CharField(required=False)

    class Meta:
        model = BadgeSerializer.Meta.model
        fields = BadgeSerializer.Meta.fields
        read_only_fields = (
            'identifier',
        )

    def validate(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return validated_data

