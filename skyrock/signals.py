from django.dispatch import Signal


user_logged_in = Signal(providing_args=["request", "user"])
# Typically followed by `user_logged_in` (unless, e-mail verification kicks in)
user_signed_up = Signal(providing_args=["request", "user"])

email_confirmed = Signal(providing_args=["request", "email_address"])
email_confirmation_sent = Signal(
    providing_args=["request", "confirmation", "signup"]
)
