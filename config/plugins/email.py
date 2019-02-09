import os

SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY', '')

ANYMAIL = {
    "SENDGRID_API_KEY": SENDGRID_API_KEY,
}

EMAIL_BACKEND = "anymail.backends.sendgrid.EmailBackend"

SERVER_EMAIL = os.environ.get('SERVER_EMAIL', '')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', '')

if os.environ.get('DEBUG', True) in ('True', 'true', True,):
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
