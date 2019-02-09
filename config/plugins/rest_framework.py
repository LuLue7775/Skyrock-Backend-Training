import datetime

from rest_framework.pagination import PageNumberPagination


ANONYMOUS_USER_ID = -1

CORS_ORIGIN_ALLOW_ALL = True

# REST_AUTH_SERIALIZERS = {
#     'LOGIN_SERIALIZER': 'administration.serializers.LoginSerializer',
#     'USER_DETAILS_SERIALIZER': 'wallet.serializers.UserInfoSerializer',
#     'PASSWORD_RESET_SERIALIZER': 'administration.serializers.PasswordResetSerializer',
# }

# REST_AUTH_REGISTER_SERIALIZERS = {
#     'REGISTER_SERIALIZER': 'administration.serializers.RegisterSerializer',
# }

# REST FRAMEWORK ~ http://www.django-rest-framework.org/
# ---------------------------------------------------------------------------------------------------------------------
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
	'DEFAULT_AUTHENTICATION_CLASSES': (
        'knox.auth.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'EXCEPTION_HANDLER': 'config.exceptions.custom_exception_handler',
}

from rest_framework.settings import reload_api_settings
reload_api_settings(setting='REST_FRAMEWORK', value=REST_FRAMEWORK)
