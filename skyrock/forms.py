import re
from urllib.parse import urlencode, unquote

from django import forms
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from allauth.account import app_settings
from allauth.account.forms import ResetPasswordForm, BaseSignupForm
from allauth.account.adapter import get_adapter
from allauth.account.utils import user_username

from skyrock.models import User


class PasswordResetForm(ResetPasswordForm):

    def save(self, request, **kwargs):
        current_site = get_current_site(request)
        email = self.cleaned_data["email"]
        token_generator = kwargs.get("token_generator", default_token_generator)

        for user in self.users:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = token_generator.make_token(user)

            from config.settings import ACCOUNT_PASSWORD_RESET_URL

            if ACCOUNT_PASSWORD_RESET_URL:
                args = '?' + urlencode({'uid': uid, 'token': token,})
                url = unquote(ACCOUNT_PASSWORD_RESET_URL + args)
            else:
                url = None

            context = {"current_site": current_site,
                       "user": user,
                       "password_reset_url": url,
                       "request": request}

            if app_settings.AUTHENTICATION_METHOD \
                    != app_settings.AuthenticationMethod.EMAIL:
                context['username'] = user_username(user)
            get_adapter(request).send_mail(
                'account/email/password_reset_key',
                email,
                context)
        return self.cleaned_data["email"]


# class SignupForm(forms.Form):
#     first_name = forms.CharField(max_length=30, label='Voornaam')
#     last_name = forms.CharField(max_length=30, label='Achternaam')

#     def signup(self, request, user):
#         user.first_name = self.cleaned_data['first_name']
#         user.last_name = self.cleaned_data['last_name']
#         user.save()