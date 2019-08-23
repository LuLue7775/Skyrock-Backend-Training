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


class ClubSerializer(serializers.ModelSerializer):
    identifier = serializers.UUIDField(read_only=True)
    #badges = BadgeSerializer(many=True)
    # projects = ProjectSerializer(many=True)

    class Meta:
        model = Club
        fields = (
            'identifier',
            'name',
            'description',
            #'badges',
            # 'projects'
        )

    def delete(self):
        self.instance.delete()


class CreateClubSerializer(ClubSerializer):
    name = serializers.CharField(required=True)
    description = serializers.CharField(required=True)
    student = serializers.CharField(required=True)

    class Meta:
        model = ClubSerializer.Meta.model
        fields = (
            'identifier',
            'name',
            'description',
            'student',
        )
        read_only_fields = (
            'identifier',
        )

    def validate(self, validated_data):
        validated_data['user'] = self.context['request'].user
        # validated_data['color'] = self.validated_data.get('color')
        return validated_data

    def create(self, validated_data):
        #colors = validated_data.get('colors')
        #projects = validated_data.get('projects')

        try:
            student = Student.objects.get(
                identifier=validated_data['student'],
                )
        except Student.DoesNotExist:
            raise exceptions.NotFound()


        club = Club.objects.create(
                name=validated_data['name'],
                description=validated_data['description'],
                student=student,
                )

        # for item in colors:
        #     try:
        #         color = Color.objects.get(identifier=item)
        #     except Color.DoesNotExist:
        #         raise serializers.ValidationError(
        #             {"color": ["The color does not exist."]})
        #     pathway.colors.add(color)

        # for item in projects:    
        #     try:
        #         project = Project.objects.get(identifier=item)
        #     except Project.DoesNotExist:
        #         raise serializers.ValidationError(
        #             {"project": ["The project does not exist."]})
        #     pathway.projects.add(project)

        return club




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
            'current_club'
        )

    def delete(self):
        self.instance.delete()


class ClientShortSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.CharField(required=True)
    phone = serializers.CharField(required=False)
    
    #student = Student.objects.filter(client= self.identifier)

    class Meta:
        model = Client
        fields = (
            'identifier',
            'first_name',
            'last_name',
            'email',
            'phone',
            
        )
        

    def delete(self):
        self.instance.delete()

class StudentSerializer(serializers.ModelSerializer):
    clubs = ClubSerializer(many=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    client = ClientShortSerializer()
    birth_date = serializers.DateField()
    language = serializers.CharField()
    # notes = serializers.CharField()
    medical_condition = serializers.CharField()

    class Meta:
        model = Student
        fields = (
            'identifier',
            'first_name',
            'last_name',
            'clubs',
            'client',
            'birth_date',
            # 'notes',
            'language',
            'medical_condition',
        )

    def delete(self):
        self.instance.delete()


class StudentShortSerializer(serializers.ModelSerializer):
    clubs = ClubSerializer(many=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    birth_date = serializers.DateField()
    language = serializers.CharField()
    # notes = serializers.CharField()
    medical_condition = serializers.CharField()

    class Meta:
        model = Student
        fields = (
            'identifier',
            'first_name',
            'last_name',
            'clubs',
            'client',
            'birth_date',
            # 'notes',
            'language',
            'medical_condition',
        )

    def delete(self):
        self.instance.delete()


class CreateStudentSerializer(StudentSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    client = serializers.CharField()
    birth_date = serializers.DateField()
    language = serializers.CharField()
    # notes = serializers.CharField()
    medical_condition = serializers.CharField()

    class Meta:
        model = StudentSerializer.Meta.model
        fields = (
            'identifier',
            'first_name',
            'last_name',
            'client',
            'birth_date',
            # 'notes',
            'language',
            'medical_condition',
        )
        read_only_fields = (
            'identifier',
        )

    def validate(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return validated_data

    def create(self, validated_data):
        try:
            client = Client.objects.get(
                identifier=validated_data['client'],
                )
        except Client.DoesNotExist:
            raise exceptions.NotFound()

        student = Student.objects.create(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            birth_date=validated_data.get('birth_date'),
            client=client,
            medical_condition=validated_data.get('medical_condition'),
            language=validated_data.get('language'),
            )

        return student


class ClientSerializer(serializers.ModelSerializer):
    student = StudentShortSerializer(many=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.CharField(required=True)
    phone = serializers.CharField(required=False)
    language = serializers.CharField(required=False)
    location = serializers.CharField(required=False)
    #student = Student.objects.filter(client= self.identifier)

    class Meta:
        model = Client
        fields = (
            'identifier',
            'first_name',
            'last_name',
            'email',
            'phone',
            'location',
            'language',
            'student',
        )
        

    def delete(self):
        self.instance.delete()


class CreateClientSerializer(ClientSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.CharField(required=True)
    phone = serializers.CharField(required=False)
    language = serializers.CharField(required=False)
    location = serializers.CharField(required=False)

    class Meta:
        model = ClientSerializer.Meta.model
        fields = (
            'identifier',
            'first_name',
            'last_name',
            'email',
            'phone',
            'location',
            'language',
        )
        read_only_fields = (
            'identifier',
        )

    def validate(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return validated_data

    def create(self, validated_data):

        client = Client.objects.create(
                first_name=validated_data['first_name'],
                last_name=validated_data['last_name'],
                email=validated_data.get('email'),
                phone=validated_data.get('phone'),
                location=validated_data.get('location'),
                language=validated_data.get('language'),

                )


        return client


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
    location = serializers.CharField()
    student = StudentSerializer()
    location = serializers.CharField()
    club = serializers.CharField()

    class Meta:
        model = Booking
        fields = (
            'location',
            'student',
            'date',
            'location',
        )

    def delete(self):
        self.instance.delete()


class CreateStudentBookingSerializer(serializers.ModelSerializer):
    location = serializers.CharField()
    student = serializers.CharField()
    date = serializers.CharField()
    club = serializers.CharField()
    #teacher = serializers.CharField()

    class Meta:
        model = Booking
        fields = (
            'location',
            'student',
            'date',
            'club',
            #'teacher',
        )

    def validate(self, validated_data):
        
        try:
            student = Student.objects.get(
                identifier=validated_data['student']
            )
            validated_data['student'] = student

        except Student.DoesNotExist:
            raise exceptions.NotFound()

        

        return validated_data

    def create(self, validated_data):

        booking = Booking.objects.create(
                student=validated_data['student'],
                location=validated_data.get('location'),
                date=validated_data.get('date'),
                club=validated_data.get('club'),
                )

        return booking

