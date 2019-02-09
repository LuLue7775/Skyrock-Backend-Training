import os

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
)

ACCOUNT_ADAPTER = 'skyrock.adapters.AccountAdapter'
ACCOUNT_EMAIL_SUBJECT_PREFIX = ''
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_AUTHENTICATION_METHOD = 'email'

ACCOUNT_EMAIL_VERIFY_URL = os.environ.get('ACCOUNT_EMAIL_VERIFY_URL')
ACCOUNT_PASSWORD_RESET_URL = os.environ.get('ACCOUNT_PASSWORD_RESET_URL')
