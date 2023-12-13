from django import forms
from django.core.exceptions import ValidationError
import re
from .models import LoginRecord, GeneratedLogin
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import get_user_model

class LoginForm(forms.Form):
    username = forms.CharField(max_length=100, required=True)
    password = forms.CharField(widget=forms.PasswordInput, required=True)

# class CreateUserForm(forms.Form):
#     username = forms.CharField(max_length=100, label='Nazwa Użytkownika')
#     password = forms.CharField(widget=forms.PasswordInput, label='Hasło')
#     email = forms.EmailField()
#     birth_date = forms.DateField(widget=forms.SelectDateWidget(years=range(1900, 2030)), label='Data Urodzenia')
#
#     def clean_password(self):
#         password = self.cleaned_data['password']
#
#         if len(password) < 8:
#             raise ValidationError("Hasło za krótkie (minimum 8 znaków)")
#
#         if not re.search("[a-z]", password) or not re.search("[A-Z]", password):
#             raise ValidationError("Brak dużej lub małej litery w haśle")
#
#         if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
#             raise ValidationError("Brak znaku specjalnego w haśle")
#
#         return password
#
#     def clean_email(self):
#         email = self.cleaned_data['email']
#
#         if '@' not in email or '.' not in email:
#             raise ValidationError("Niepoprawny adres email")
#
#         return email

class CreateUserForm(forms.Form):
    username = forms.CharField(max_length=100, label='Nazwa Użytkownika')
    password = forms.CharField(widget=forms.PasswordInput, label='Hasło')
    confirm_password = forms.CharField(widget=forms.PasswordInput, label='Potwierdź Hasło')
    email = forms.EmailField()
    birth_date = forms.DateField(widget=forms.SelectDateWidget(years=range(1900, 2030)), label='Data Urodzenia')

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and confirm_password and password != confirm_password:
            raise ValidationError("Hasła nie są identyczne")

        return cleaned_data

    def clean_password(self):
        password = self.cleaned_data['password']

        if len(password) < 8:
            raise ValidationError("Hasło za krótkie (minimum 8 znaków)")

        if not re.search("[a-z]", password) or not re.search("[A-Z]", password):
            raise ValidationError("Brak dużej lub małej litery w haśle")

        if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValidationError("Brak znaku specjalnego w haśle")

        return password

    def clean_email(self):
        email = self.cleaned_data['email']

        if '@' not in email or '.' not in email:
            raise ValidationError("Niepoprawny adres email")

        return email


class ForgotPasswordForm(forms.Form):
    username = forms.CharField(max_length=100)
    email = forms.EmailField()

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        email = cleaned_data.get('email')

        # Sprawdź, czy podany użytkownik istnieje
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise forms.ValidationError("Podany użytkownik nie istnieje.")

        # Sprawdź, czy podany email jest przypisany do użytkownika
        if user.email != email:
            raise forms.ValidationError("Błędny adres email.")

        return cleaned_data

class AddManualForm(forms.ModelForm):
    class Meta:
        model = LoginRecord
        fields = ['page_name', 'category', 'login', 'password']

    page_name = forms.CharField(label='Nazwa strony')
    login = forms.CharField(label='Login')
    password = forms.CharField(label='Hasło')
    category = forms.ChoiceField(
        choices=[
            ('social_media', 'Social Media'),
            ('email', 'Email'),
            ('other', 'Inne'),
            ('savings', 'Oplaty'),
            ('shops', 'Sklepy'),
            ('work', 'Praca')
        ],
        label='Kategoria Strony'
    )
class AddGenerateForm(forms.ModelForm):
    class Meta:
        model = GeneratedLogin
        fields = ['page_name', 'category', 'login', 'min_password_length', 'require_uppercase', 'require_lowercase',
                  'require_special_characters']

    category = forms.ChoiceField(
        choices=[
            ('social_media', 'Social Media'),
            ('email', 'Email'),
            ('other', 'Inne'),
            ('savings', 'Oplaty'),
            ('shops', 'Sklepy'),
            ('work', 'Praca')
        ],
         label='Kategoria Storny'
    )

    page_name = forms.CharField(label='Nazwa strony')
    login = forms.CharField(label='Login')
    min_password_length = forms.IntegerField(min_value=1, label='Minimalna ilość znaków w haśle')
    require_uppercase = forms.BooleanField(required=False, label='Czy hasło musi zawierać duże litery?')
    require_lowercase = forms.BooleanField(required=False, label='Czy hasło musi zawierać małe litery?')
    require_special_characters = forms.BooleanField(required=False, label='Czy hasło musi zawierać znaki specjalne?')

class GeneratePasswordForm(forms.Form):
    min_password_length = forms.IntegerField(min_value=1, label='Minimalna liczba znaków')
    require_uppercase = forms.BooleanField(required=False, label='Czy musi zawierać duże litery?')
    require_lowercase = forms.BooleanField(required=False, label='Czy musi zawierać małe litery?')
    require_special_characters = forms.BooleanField(required=False, label='Czy musi zawierać znaki specjalne?')


class ChangeEmailForm(forms.Form):
    new_email = forms.EmailField(label='Nowy email')

class ChangeDOBForm(forms.Form):
    new_dob = forms.DateField(widget=forms.SelectDateWidget(years=range(1900, 2030)), label='Nowa data urodzenia')

class DeleteAccountForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput, label='Podaj hasło')
    dob = forms.DateField(widget=forms.SelectDateWidget(years=range(1900, 2030)), label='Podaj datę urodzenia')

class EditLoginForm(forms.ModelForm):
    class Meta:
        model = LoginRecord
        fields = ['login']
        labels = {'login': 'Nowy login'}

class EditPasswordForm(forms.ModelForm):
    class Meta:
        model = LoginRecord
        fields = ['password']
        labels = {'password': 'Nowe hasło'}

