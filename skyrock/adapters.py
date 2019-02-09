from urllib.parse import urlencode, unquote


from allauth.account.adapter import DefaultAccountAdapter

from logging import getLogger

logger = getLogger('django')


class AccountAdapter(DefaultAccountAdapter):
    def get_email_confirmation_url(self, request, emailconfirmation):
        from config.settings import ACCOUNT_EMAIL_VERIFY_URL

        if ACCOUNT_EMAIL_VERIFY_URL:
            args = '?' + urlencode({'key': emailconfirmation.key,})
            return unquote(ACCOUNT_EMAIL_VERIFY_URL + args)

        return None
