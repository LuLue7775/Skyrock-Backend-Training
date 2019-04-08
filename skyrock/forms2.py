from allauth.account.forms import forms 
from skyrock.enums import *


class CustomSignupForm(forms.Form):
    role = forms.ChoiceField(
        choices=Role.choices())
    

    def signup(self, request, user):
        user.role = self.cleaned_data['role']
        print(user.role)
        user.save()

