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
    role = serializers.ChoiceField(
        required=False,
        source='role.value',
        choices=Role.choices())
    
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'created', 'updated', 'role')
        read_only_field = ('created', 'updated',)

    def validate(self, validated_data):
        return validated_data


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
    role = serializers.ChoiceField(
        required=False,
        choices=Role.choices())

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
        user.role = request.data['role']
        user.save()
        
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


# class ColorSerializer(serializers.ModelSerializer):
#     identifier = serializers.UUIDField(read_only=True)
#     class Meta:
#         model = Color
#         fields = (
#             'identifier',
#             'name',
#             'description'
#         )

#     def delete(self):
#         self.instance.delete()


# class ChallengeSerializer(serializers.ModelSerializer):
#     identifier = serializers.UUIDField(read_only=True)
#     class Meta:
#         model = Challenge
#         fields = (
#             'identifier',
#             'name',
#             'description'
#         )

#     def delete(self):
#         self.instance.delete()


# class TaskSerializer(serializers.ModelSerializer):
#     identifier = serializers.UUIDField(read_only=True)
#     class Meta:
#         model = Task
#         fields = (
#             'identifier',
#             'name',
#             'description',
#         )

#     def delete(self):
#         self.instance.delete()


# class ProjectSerializer(serializers.ModelSerializer):
#     identifier = serializers.UUIDField(read_only=True)
#     tasks = TaskSerializer(many=True)
#     challenges = ChallengeSerializer(many=True)

#     class Meta:
#         model = Project
#         fields = (
#             'identifier',
#             'name',
#             'description',
#             'tasks',
#             'challenges'
#         )
#     def delete(self):
#         self.instance.delete()


class PathwaySerializer(serializers.ModelSerializer):
    identifier = serializers.UUIDField(read_only=True)
    # colors = ColorSerializer(many=True)
    # projects = ProjectSerializer(many=True)

    class Meta:
        model = Pathway
        fields = (
            'identifier',
            'name',
            'description',
            # 'colors',
            # 'projects'
        )

    def delete(self):
        self.instance.delete()


# class BadgeSerializer(serializers.ModelSerializer):
#     identifier = serializers.UUIDField(read_only=True)
#     class Meta:
#         model = Badge
#         fields = (
#             'identifier',
#             'name',
#             'description'
#         )

#     def delete(self):
#         self.instance.delete()


# class TagSerializer(serializers.ModelSerializer):
#     identifier = serializers.UUIDField(read_only=True)
#     class Meta:
#         model = Tag
#         fields = (
#             'name'
#         )

#     def delete(self):
#         self.instance.delete()
        

# class CreateTagSerializer(TagSerializer):
#     name = serializers.CharField(required=True)

#     class Meta:
#         model = ColorSerializer.Meta.model
#         fields = ColorSerializer.Meta.fields


# class CreateColorSerializer(ColorSerializer):
#     name = serializers.CharField(required=True)
#     description = serializers.CharField(required=True)

#     class Meta:
#         model = ColorSerializer.Meta.model
#         fields = ColorSerializer.Meta.fields
#         read_only_fields = (
#             'identifier',
#         )


class CreatePathwaySerializer(PathwaySerializer):
    name = serializers.CharField(required=True)
    description = serializers.CharField(required=True)
    # colors = serializers.ListField(required=True)
    # projects = serializers.ListField(required=True)

    class Meta:
        model = PathwaySerializer.Meta.model
        fields = (
            'identifier',
            'name',
            'description',
            # 'colors',
            # 'projects',
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

        
# class CreateProjectSerializer(ProjectSerializer):
#     name = serializers.CharField(required=True)
#     description = serializers.CharField(required=True)
#     tasks = serializers.ListField(required=True)
#     challenges = serializers.ListField(required=False)

#     class Meta:
#         model = ProjectSerializer.Meta.model
#         fields = (
#             'identifier',
#             'name',
#             'description',
#             'tasks',
#             'challenges'
#         )
#         read_only_fields = (
#             'identifier',
#         )

#     def validate(self, validated_data):
#         return validated_data

#     def create(self, validated_data):
#         tasks = validated_data.get('tasks')
#         challenges = validated_data.get('challenges')

#         project = Project.objects.create(
#                 name=validated_data['name'],
#                 description=validated_data['description'],
#                 )

#         for item in tasks:
#             try:
#                 task = Task.objects.get(identifier=item)
#             except Task.DoesNotExist:
#                 raise serializers.ValidationError(
#                     {"tasks": ["The task does not exist."]})
#             project.tasks.add(task)

#         for items in challenges:
#             try:
#                 challenge = Challenge.objects.get(identifier=items)
#             except Challenge.DoesNotExist:
#                 raise serializers.ValidationError(
#                     {"challenge": ["The challenge does not exist."]})
#             project.challenges.add(challenge)

#         return project


# class CreateTaskSerializer(TaskSerializer):
#     name = serializers.CharField(required=True)
#     description = serializers.CharField(required=True)
#     tags = serializers.ListField(required=True)

#     class Meta:
#         model = TaskSerializer.Meta.model
#         fields = (
#             'identifier',
#             'name',
#             'description',
#             'tags',
#         )
#         read_only_fields = (
#             'identifier',
#         )

#     def validate(self, validated_data):
#         return validated_data

#     def create(self, validated_data):
#         tags = validated_data.get('tags')

#         task = Task.objects.create(
#                 name=validated_data['name'],
#                 description=validated_data['description'],
#                 )

#         for item in tags:
            
#             tag = Tag.objects.get_or_create(name=item)
#             task.tags.add(tag)

#         return task


# class CreateChallengeSerializer(ChallengeSerializer):
#     name = serializers.CharField(required=True)
#     description = serializers.CharField(required=True)
#     tags = serializers.ListField(required=True)

#     class Meta:
#         model = ChallengeSerializer.Meta.model
#         fields = (
#             'identifier',
#             'name',
#             'description',
#             'tags',
#         )
#         read_only_fields = (
#             'identifier',
#         )

#     def validate(self, validated_data):
#         return validated_data

#     def create(self, validated_data):
#         tags = validated_data.get('tags')

#         challenge = Challenge.objects.create(
#                 name=validated_data['name'],
#                 description=validated_data['description'],
#                 )

#         for item in tags:
            
#             tag = Tag.objects.get_or_create(name=item)
#             task.tags.add(tag)

#         return challenge


# class CreateTaskSerializer(TaskSerializer):
#     name = serializers.CharField(required=False)
#     description = serializers.CharField(required=False)

#     class Meta:
#         model = TaskSerializer.Meta.model
#         fields = TaskSerializer.Meta.fields
#         read_only_fields = (
#             'identifier',
#         )

# class CreateBadgeSerializer(BadgeSerializer):
#     name = serializers.CharField(required=False)
#     description = serializers.CharField(required=False)
#     tag = serializers.CharField(required=False)
#     class Meta:
#         model = BadgeSerializer.Meta.model
#         fields = BadgeSerializer.Meta.fields
#         read_only_fields = (
#             'identifier',
#         )

#     def validate(self, validated_data):

#         try:
#             tag = Tag.objects.get(
#                 name=validated_data('tag'),
#             )
#             validated_data['tag'] = tag
#         except Tag.DoesNotExist:
#             raise exceptions.NotFound()

#         return validated_data


class StudentPathwaySerializer(serializers.ModelSerializer):
    identifier = serializers.UUIDField(read_only=True)
    pathway = PathwaySerializer()
    complete = serializers.BooleanField()

    class Meta:
        model = Pathway
        fields = (
            'identifier',
            'pathway',
            'complete'
        )

    def delete(self):
        self.instance.delete()

class ParentSerializer(serializers.ModelSerializer):
    identifier = serializers.UUIDField(read_only=True)
    email = serializers.CharField()
    phone = serializers.IntegerField()
    payment = serializers.CharField()
    cost = serializers.IntegerField()
    name = serializers.CharField(required=False)

    class Meta:
        model = Parent
        fields = (
            'identifier',
            'name',
            'email',
            'phone',
            'payment',
            'cost',
        )

    def delete(self):
        self.instance.delete()

class StudentSerializer(serializers.ModelSerializer):
    pathways = PathwaySerializer(many=True)
    parent = ParentSerializer()
    age = serializers.IntegerField()
    email = serializers.CharField()
    phone = serializers.CharField()
    current_teacher =  serializers.CharField()

    class Meta:
        model = Student
        fields = (
            'identifier',
            'name',
            'pathways',
            'parent',
            'age',
            'email',
            'phone',
            'hours',
            'current_teacher',
            'current_pathway'
        )

    def delete(self):
        self.instance.delete()

class ShortStudentSerializer(serializers.ModelSerializer):
   
    class Meta:
        model = Student
        fields = (
            'identifier',
            'name',
            'age',
            'email',
            'phone',
            'hours',
            'current_teacher',
            'current_pathway'
        )

    def delete(self):
        self.instance.delete()



class CreateStudentSerializer(StudentSerializer):
    name = serializers.CharField(required=True)
    pathways = serializers.ListField()
    parent = serializers.CharField(required=True)
    age = serializers.IntegerField(required=True)
    hours = serializers.IntegerField()
    email = serializers.CharField()
    phone = serializers.CharField()
    parent_email = serializers.CharField()
    parent_phone = serializers.CharField()
    parent_cost = serializers.IntegerField()
    parent_payment = serializers.CharField()
    parent_name = serializers.CharField()
    current_teacher = serializers.CharField()
    current_pathway = serializers.CharField()

    class Meta:
        model = StudentSerializer.Meta.model
        fields = (
            'identifier',
            'name',
            'pathways',
            'parent',
            'age',
            'email',
            'phone',
            'hours',
            'current_teacher',
            'current_pathway',
            'parent_name',
            'parent_payment',
            'parent_cost',
            'parent_phone',
            'parent_email'
        )
        read_only_fields = (
            'identifier',
        )

    def validate(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return validated_data

    def create(self, validated_data):
        pathway = validated_data.get('pathways')

        parent = Parent.objects.create(
                name=validated_data['name'],
                email=validated_data.get('parent_email'),
                phone=validated_data.get('parent_phone'),
                cost=validated_data.get('parent_cost'),
                payment=validated_data.get('parent_payment'),
                

                )

        student = Student.objects.create(
                name=validated_data['name'],
                age=validated_data.get('age'),
                email=validated_data.get('email'),
                phone=validated_data.get('phone'),
                hours=validated_data.get('hours'),
                parent=parent,
                current_teacher=validated_data.get('current_teacher'),
                current_pathway=validated_data.get('current_pathway'),
                )

        for item in pathway:   
            try:
                project = Pathway.objects.get(identifier=item)
            except Pathway.DoesNotExist:
                raise serializers.ValidationError(
                    {"project": ["The pathway does not exist."]})
            student.pathways.add(project)

        return student


class StudentAttendanceSerializer(serializers.ModelSerializer):
    student = ShortStudentSerializer()
    status = serializers.ChoiceField(
                required=True,
                source='status.value',

                choices=Attendance_status.choices())

    class Meta:
        model = Attendance
        fields = (
            'identifier',
             'status',
            'student',
            'date',
            
        )

    def delete(self):
        self.instance.delete()


class CreateStudentAttendanceSerializer(StudentAttendanceSerializer):
    date = serializers.CharField()
    student = serializers.CharField()
    status = serializers.ChoiceField(
                required=True,
                source='status.value',

                choices=Attendance_status.choices())
    
    class Meta:
        model = Attendance
        fields = (
            'identifier',
            'student',
            'status',
            'date',
        )

    def validate(self, validated_data):

        try:
            student = Student.objects.get(identifier = validated_data.get('student'))
            validated_data["student"] = student
        except Student.DoesNotExist:
                raise serializers.ValidationError(
                    {"attendance": ["The student does not exist."]})

        validated_data['status'] = Attendance_status(
            validated_data['status']['value']
        )

        return validated_data

    def create(self, validated_data):
        return Attendance.objects.create(
            **validated_data
        )
       
class StudentBookingSerializer(serializers.ModelSerializer):
    location = serializers.ChoiceField(
                required=True,
                source='status.value',
                choices=Location.choices())
    student = StudentSerializer()

    class Meta:
        model = Booking
        fields = (
            'location',
            'student',
            'date',
            'code',
            'class_type',
            'teacher',
            'client_email',
            'client_name'
        )

    def delete(self):
        self.instance.delete()


class CreateStudentBookingSerializer(serializers.ModelSerializer):
    location = serializers.CharField()
    student = serializers.CharField()
    date = serializers.CharField()
    code = serializers.CharField()
    class_type = serializers.CharField()
    teacher = serializers.CharField()
    client_email = serializers.CharField()
    client_name = serializers.CharField()

    class Meta:
        model = Booking
        fields = (
            'location',
            'student',
            'date',
            'code',
            'class_type',
            'teacher',
            'client_email',
            'client_name'
        )

    def validate(self, validated_data):
        
        if validated_data.get('location') == 1 : 
            validated_data['location'] = Location.TIANMU
        elif validated_data.get('location') == 2 : 
            validated_data['location'] = Location.DAZHI
        else :
            validated_data['location'] = Location.NONE

        print(validated_data.get('date'))

        

        return validated_data
        