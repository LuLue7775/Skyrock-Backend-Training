import os

SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY', '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')

ANYMAIL = {
    "SENDGRID_API_KEY": SENDGRID_API_KEY,
}

EMAIL_BACKEND = "anymail.backends.sendgrid.EmailBackend"

SERVER_EMAIL = os.environ.get('SERVER_EMAIL', 'stephan@skyrockprojects.com')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'info@skyrockprojects.com')

# if os.environ.get('DEBUG', True) in ('True', 'true', True,):
#     EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
