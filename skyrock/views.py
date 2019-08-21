import uuid
from collections import OrderedDict
from functools import partial

from rest_framework.decorators import api_view, permission_classes
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework import exceptions, status, filters
from rest_framework.pagination import PageNumberPagination
from allauth.account.models import EmailAddress
from allauth.account.utils import complete_signup
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC
from allauth.account import app_settings as allauth_settings
from knox.auth import TokenAuthentication
from knox.models import AuthToken
from django.contrib.auth import login as django_login, logout as django_logout
from django.utils import timezone
from django.db.models import Q

from config import settings
from skyrock.models import *
from skyrock.serializers import * 
from skyrock.authentication import *
from skyrock.permissions import *
from skyrock.pagination import *

from logging import getLogger

logger = getLogger('django')


@api_view(['GET'])
@permission_classes([AllowAny, ])
def root(request, format=None):
    return Response(
        [
            {'User': OrderedDict([
                ('Register', reverse('skyrock:user-register',
                    request=request,
                    format=format)),
                ('Login', reverse('skyrock:user-login',
                    request=request,
                    format=format)),
                ('Logout', reverse('skyrock:user-logout',
                    request=request,
                    format=format)),
                ('Password Change', reverse('skyrock:user-password-change',
                    request=request,
                    format=format)),
                ('Password Reset', reverse('skyrock:user-password-reset',
                    request=request,
                    format=format)),
                ('Course', reverse('skyrock:user-course-view',
                    request=request,
                    format=format)),
                ('Booking', reverse('skyrock:user-booking-view',
                    request=request,
                    format=format)),
                ('Student', reverse('skyrock:user-student-view',
                    request=request,
                    format=format)),
                ('Client', reverse('skyrock:user-parents-view',
                    request=request,
                    format=format)),
                    
                    
            ])},
        ])


class ListModelMixin(object):
    """
    List a queryset.
    """

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response({'status': 'success', 'data': serializer.data})


class ListAPIView(ListModelMixin,
                  GenericAPIView):
    """
    Concrete view for listing a queryset.
    """

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)


class RegisterView(GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = (AllowAny, )

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save(request)
        token = AuthToken.objects.create(user=user)

        complete_signup(
            self.request._request,
            user,
            allauth_settings.EMAIL_VERIFICATION,
            None
        )

        return Response(
            {'status': 'success',
             'data': TokenSerializer({'user': user, 'token': token}).data},
            status=status.HTTP_201_CREATED
        )


class LoginView(GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        request = request
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer_class = TokenSerializer
        user = serializer.validated_data.get('user')

        # Before we create a new token, delete any other that might not have
        # been deleted because tokens are created on session login
        AuthToken.objects.exclude(expires=None)\
            .filter(user=user, expires__lt=timezone.now()).delete()
        token = AuthToken.objects.create(user=user)

        if getattr(settings, 'REST_SESSION_LOGIN', True):
            django_login(request, user)
        else:
            user_logged_in.send(sender=user.__class__, request=request,
                                user=user, token_key=token.token_key)

        serializer = serializer_class(instance={'user': user, 'token': token},
                                      context={'request': self.request})

        return Response({'status': 'success', 'data': serializer.data},
                        status=status.HTTP_200_OK)


class LogoutView(GenericAPIView):
    serializer_class = LogoutSerializer

    def post(self, request, *args, **kwargs):
        if hasattr(request.successful_authenticator, 'auth_class'):
            is_token_authenticated = (
                issubclass(request.successful_authenticator.auth_class, TokenAuthentication),
                request.auth is not None
            )
        else:
            is_token_authenticated = (
                isinstance(request.successful_authenticator, TokenAuthentication),
                request.auth is not None
            )

        if all(is_token_authenticated):
            if request._auth.expires is not None:
                request._auth.delete()
            user_logged_out.send(sender=request.user.__class__,
                                 request=request, user=request.user)
        else:
            django_logout(request)

        return Response(
            {"status": 'success'},
            status=status.HTTP_200_OK
        )


class PasswordChangeView(GenericAPIView):
    serializer_class = PasswordChangeSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"status": 'success'})


class PasswordResetView(GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"status": 'success'}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"status": 'success'})


class ResendVerifyEmailView(GenericAPIView):
    allowed_methods = ('POST',)
    serializer_class = ResendVerifyEmailSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        try:
            user = EmailAddress.objects.get(email__iexact=email).user
        except EmailAddress.DoesNotExist:
            # Do not inform a user about the existence oemail__iexactf an email.
            # Return "success" regardless of an actual email getting sent.
            return Response({'status': 'success'})

        try:
            from allauth.account.utils import send_email_confirmation
            send_email_confirmation(request._request, user, signup=True)
        except Exception as exc:
            logger.exception(exc)
            raise exceptions.ValidationError({'non_field_errors':
                ['Error sending the verification email.']})

        return Response({'status': 'success'})


class VerifyEmailView(GenericAPIView):
    allowed_methods = ('POST',)
    serializer_class = VerifyEmailSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        key = request.data.get('key')

        if not key:
            raise exceptions.ValidationError(
                {'key': ['The key is invalid.']})

        # Get HMAC confirmation
        emailconfirmation = EmailConfirmationHMAC.from_key(key)

        # Alternatively, get normal confirmation
        if not emailconfirmation:
            try:
                queryset = EmailConfirmation.objects.all_valid()
                emailconfirmation = queryset.get(key=key.lower())
            except AttributeError:
                raise exceptions.ValidationError(
                    {'key': ['The key is invalid.']})
            except EmailConfirmation.DoesNotExist:
                raise exceptions.ValidationError(
                    {'key': ['The key is invalid or has expired.']})

        emailconfirmation.confirm(self.request)
        return Response({'status': 'success'})


class AdminClubCreateView(ListAPIView):
    allowed_methods = ('GET','POST')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = ClubSerializer    

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateClubSerializer
        return super().get_serializer_class()

    def get_queryset(self):
        return Club.objects.filter(
        ).order_by('-created')

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success', 'data': ClubSerializer(instance).data},
            status=status.HTTP_201_CREATED
        )


class AdminClubView(GenericAPIView):
    allowed_methods = ('GET','PATCH', 'DELETE')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = ClubSerializer  

    def delete(self, request, *args, **kwargs):
        try:
            club = Club.objects.get(
                identifier=kwargs['id']
            )
        except Club.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(club)
        instance = serializer.delete()
        return Response({'status': 'success'})

    def get(self, request, *args, **kwargs):
        try:
            club = Club.objects.get(
                identifier=str(kwargs['id']),
            )
        except Club.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(club)
        return Response({'status': 'success', 'data': serializer.data})

    def patch(self, request, *args, **kwargs):
        try:
            club = Club.objects.get(
                identifier=kwargs['id'],
            )
        except Club.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(
            Club, 
            data=request.data,
            partial=True)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success',
             'data': ClubSerializer(instance).data}
        )


class AdminStudentCreateView(ListAPIView):
    allowed_methods = ('GET','POST')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = StudentSerializer    

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateStudentSerializer
        return super().get_serializer_class()

    def get_queryset(self):
        return Student.objects.filter(
        ).order_by('-created')

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success', 'data': StudentSerializer(instance).data},
            status=status.HTTP_201_CREATED
        )


class AdminStudentView(GenericAPIView):
    allowed_methods = ('GET','PATCH', 'DELETE')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = StudentSerializer  

    def delete(self, request, *args, **kwargs):
        try:
            student = Student.objects.get(
                identifier=kwargs['id']
            )
        except Student.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(student)
        instance = serializer.delete()
        return Response({'status': 'success'})

    def get(self, request, *args, **kwargs):
        try:
            student = Student.objects.get(
                identifier=str(kwargs['id']),
            )
        except Student.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(student)
        return Response({'status': 'success', 'data': serializer.data})

    def patch(self, request, *args, **kwargs):
        try:
            student = Student.objects.get(
                identifier=kwargs['id'],
            )
        except Student.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(
            Student, 
            data=request.data,
            partial=True)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success',
             'data': StudentSerializer(instance).data}
        )


class AdminStudentAttendanceView(ListAPIView):
    allowed_methods = ('GET','POST')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = StudentAttendanceSerializer    

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateStudentAttendanceSerializer
        return super().get_serializer_class()

    def get_queryset(self, **kwargs):
        try:
            student = Student.objects.get(
                identifier = self.kwargs['id'])
        except Student.DoesNotExist:
            raise serializers.ValidationError(
                    {"attendance": ["The student does not exist."]})

        return Attendance.objects.filter(
            student=student
            ).order_by('-created')

    def post(self, request, *args, **kwargs):
        request.data['student'] = kwargs["id"]
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success', 'data': StudentAttendanceSerializer(instance).data},
            status=status.HTTP_201_CREATED
        )


class CreateAdminStudentAttendanceView(GenericAPIView):
    allowed_methods = ('GET','PATCH', 'DELETE')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = StudentAttendanceSerializer  

    def delete(self, request, *args, **kwargs):
        try:
            attendance = Attendance.objects.get(
                identifier=kwargs['id']
            )
        except Attendance.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(attendance)
        instance = serializer.delete()
        return Response({'status': 'success'})

    def get(self, request, *args, **kwargs):
        try:
            attendance = Attendance.objects.get(
            )
        except Attendance.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(attendance)
        return Response({'status': 'success', 'data': serializer.data})

    def patch(self, request, *args, **kwargs):
        try:
            attendance = Attendance.objects.get(
                identifier=kwargs['id'],
            )
        except Attendance.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(
            Attendance, 
            data=request.data,
            partial=True)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success',
             'data': StudentAttendanceSerializer(instance).data}
        )


class CreateAdminBookingView(ListAPIView):
    allowed_methods = ('GET','POST')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = StudentBookingSerializer    

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateStudentBookingSerializer
        return super().get_serializer_class()

    def get_queryset(self, **kwargs):
        

        return Booking.objects.filter(
            
            ).order_by('-created')

    def post(self, request, *args, **kwargs):
        # request.data['student'] = kwargs["id"]
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success', 'data': StudentBookingSerializer(instance).data},
            status=status.HTTP_201_CREATED
        )


class AdminBookingView(GenericAPIView):
    allowed_methods = ('GET','PATCH', 'DELETE')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = StudentBookingSerializer  

    def delete(self, request, *args, **kwargs):
        try:
            attendance = Booking.objects.get(
                identifier=kwargs['booking']
            )
        except Booking.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(attendance)
        instance = serializer.delete()
        return Response({'status': 'success'})

    def get(self, request, *args, **kwargs):
        try:
            booking = Booking.objects.get(
                identifier=kwargs['booking']
            )
        except Booking.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(booking)
        return Response({'status': 'success', 'data': serializer.data})

    def patch(self, request, *args, **kwargs):
        try:
            booking = Booking.objects.get(
                identifier=kwargs['id'],
            )
        except Booking.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(
            Booking, 
            data=request.data,
            partial=True)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success',
             'data': StudentBookingSerializer(instance).data}
        )


class AdminStudentBookingView(GenericAPIView):
    allowed_methods = ('GET','PATCH', 'DELETE')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = StudentBookingSerializer  

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateStudentBookingSerializer
        return super().get_serializer_class()

    def get_queryset(self, **kwargs):
        try:
            student = Booking.objects.get(
                identifier = self.kwargs['id'])
        except Booking.DoesNotExist:
            raise serializers.ValidationError(
                    {"booking": ["The booking does not exist."]})

        return Booking.objects.filter(
            
            ).order_by('-created')

    def post(self, request, *args, **kwargs):
        request.data['student'] = kwargs["booking"]
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success', 'data': StudentBookingSerializer(instance).data},
            status=status.HTTP_201_CREATED
        )


class StudentBookingListView(ListAPIView):
    allowed_methods = ('GET')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = StudentBookingSerializer    

    def get_queryset(self, **kwargs):
    
        return Booking.objects.filter(
            
            ).order_by('-created')


class AdminBookingView(GenericAPIView):
    allowed_methods = ('GET','PATCH', 'DELETE')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = StudentBookingSerializer  

    def delete(self, request, *args, **kwargs):
        try:
            attendance = Booking.objects.get(
                identifier=kwargs['booking']
            )
        except Booking.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(attendance)
        instance = serializer.delete()
        return Response({'status': 'success'})

    def get(self, request, *args, **kwargs):
        try:
            booking = Booking.objects.get(
                identifier=kwargs['booking']
            )
        except Booking.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(booking)
        return Response({'status': 'success', 'data': serializer.data})

    def patch(self, request, *args, **kwargs):
        try:
            booking = Booking.objects.get(
                identifier=kwargs['id'],
            )
        except Booking.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(
            Booking, 
            data=request.data,
            partial=True)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success',
             'data': StudentBookingSerializer(instance).data}
        )


class AdminStudentBookingView(GenericAPIView):
    allowed_methods = ('GET','PATCH', 'DELETE')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = StudentBookingSerializer  

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateStudentBookingSerializer
        return super().get_serializer_class()

    def get_queryset(self, **kwargs):
        try:
            student = Booking.objects.get(
                identifier = self.kwargs['id'])
        except Booking.DoesNotExist:
            raise serializers.ValidationError(
                    {"booking": ["The booking does not exist."]})

        return Booking.objects.filter(
            
            ).order_by('-created')

    def post(self, request, *args, **kwargs):
        request.data['student'] = kwargs["booking"]
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success', 'data': StudentBookingSerializer(instance).data},
            status=status.HTTP_201_CREATED
        )


class AdminClientCreateView(ListAPIView):
    allowed_methods = ('GET','POST')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = ClientSerializer    

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateStudentSerializer
        return super().get_serializer_class()

    def get_queryset(self):
        return Client.objects.filter(
        ).order_by('-created')

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success', 'data': ClientSerializer(instance).data},
            status=status.HTTP_201_CREATED
        )


class AdminClientView(GenericAPIView):
    allowed_methods = ('GET','PATCH', 'DELETE')
    #authentication_classes = (AdminAuthentication,)
    serializer_class = ClientSerializer  

    def delete(self, request, *args, **kwargs):
        try:
            client = Client.objects.get(
                identifier=kwargs['id']
            )
        except Client.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(client)
        instance = serializer.delete()
        return Response({'status': 'success'})

    def get(self, request, *args, **kwargs):
        try:
            client = Client.objects.get(
                identifier=str(kwargs['id']),
            )
        except Client.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(client)
        return Response({'status': 'success', 'data': serializer.data})

    def patch(self, request, *args, **kwargs):
        try:
            client = Student.objects.get(
                identifier=kwargs['id'],
            )
        except Client.DoesNotExist:
            raise exceptions.NotFound()

        serializer = self.get_serializer(
            Client, 
            data=request.data,
            partial=True)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return Response(
            {'status': 'success',
             'data': ClientSerializer(instance).data}
        )