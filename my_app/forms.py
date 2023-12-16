from django import forms
from django.core.exceptions import ValidationError
import re
from .models import LoginRecord, GeneratedLogin, PageCategory
from django.contrib.auth import get_user_model

# Login Form
class LoginForm(forms.Form):
    """
    Form for user login.
    """
    username = forms.CharField(max_length=100, required=True)
    password = forms.CharField(widget=forms.PasswordInput, required=True)

# Create User Form
class CreateUserForm(forms.Form):
    """
    Form for user registration.
    """
    username = forms.CharField(max_length=100, label='Username')
    password = forms.CharField(widget=forms.PasswordInput, label='Password')
    confirm_password = forms.CharField(widget=forms.PasswordInput, label='Confirm Password')
    email = forms.EmailField()
    birth_date = forms.DateField(widget=forms.SelectDateWidget(years=range(1900, 2030)), label='Birth Date')

    def clean(self):
        """
        Custom validation for password matching.
        """
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and confirm_password and password != confirm_password:
            raise ValidationError("Passwords do not match")

        return cleaned_data

    def clean_password(self):
        """
        Custom validation for password complexity.
        """
        password = self.cleaned_data['password']

        if len(password) < 8:
            raise ValidationError("Password is too short (minimum 8 characters)")

        if not re.search("[a-z]", password) or not re.search("[A-Z]", password):
            raise ValidationError("Password must contain both uppercase and lowercase letters")

        if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValidationError("Password must contain at least one special character")

        return password

    def clean_email(self):
        """
        Custom validation for a valid email address.
        """
        email = self.cleaned_data['email']

        if '@' not in email or '.' not in email:
            raise ValidationError("Invalid email address")

        return email

# Forgot Password Form
class ForgotPasswordForm(forms.Form):
    """
    Form for password recovery.
    """
    username = forms.CharField(max_length=100)
    email = forms.EmailField()

    def clean(self):
        """
        Custom validation for checking if the user exists and email matches.
        """
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        email = cleaned_data.get('email')

        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise forms.ValidationError("User does not exist.")

        if user.email != email:
            raise forms.ValidationError("Incorrect email address.")

        return cleaned_data

# Add Manual Form
class AddManualForm(forms.ModelForm):
    """
    Form for manually adding login records.
    """
    class Meta:
        model = LoginRecord
        fields = ['page_name', 'category', 'login', 'password']

    page_name = forms.CharField(label='Strona:')
    login = forms.CharField(label='Login:')
    password = forms.CharField(label='Hasło:')
    category = forms.ModelChoiceField(queryset=PageCategory.objects.all(), label='Kategoria Strony:')


# Add Generate Form
class AddGenerateForm(forms.ModelForm):
    """
    Form for adding generated login records.
    """
    class Meta:
        model = GeneratedLogin
        fields = ['page_name', 'category', 'login', 'min_password_length', 'require_uppercase', 'require_lowercase',
                  'require_special_characters']

    page_name = forms.CharField(label='Strona:')
    category = forms.ModelChoiceField(queryset=PageCategory.objects.all(), label='Kategoria strony:')
    login = forms.CharField(label='Login:')
    min_password_length = forms.IntegerField(min_value=1, label='Minimalna długość hasła')
    require_uppercase = forms.BooleanField(required=False, label='Wymaga dużych liter')
    require_lowercase = forms.BooleanField(required=False, label='Wymaga małych liter')
    require_special_characters = forms.BooleanField(required=False, label='Wymaga znaków specjalnych')

# Generate Password Form
class GeneratePasswordForm(forms.Form):
    """
    Form for generating passwords.
    """
    min_password_length = forms.IntegerField(min_value=1, label='Minimum Password Length')
    require_uppercase = forms.BooleanField(required=False, label='Require Uppercase Letters')
    require_lowercase = forms.BooleanField(required=False, label='Require Lowercase Letters')
    require_special_characters = forms.BooleanField(required=False, label='Require Special Characters')

# Change Email Form
class ChangeEmailForm(forms.Form):
    """
    Form for changing user email.
    """
    new_email = forms.EmailField(label='New Email')

# Change Date of Birth Form
class ChangeDOBForm(forms.Form):
    """
    Form for changing user date of birth.
    """
    new_dob = forms.DateField(widget=forms.SelectDateWidget(years=range(1900, 2030)), label='New Date of Birth')

# Delete Account Form
class DeleteAccountForm(forms.Form):
    """
    Form for deleting user account.
    """
    password = forms.CharField(widget=forms.PasswordInput, label='Enter Password')
    dob = forms.DateField(widget=forms.SelectDateWidget(years=range(1900, 2030)), label='Enter Date of Birth')

# Edit Login Form
class EditLoginForm(forms.ModelForm):
    """
    Form for editing login information.
    """
    class Meta:
        model = LoginRecord
        fields = ['login']
        labels = {'login': 'New Login'}

# Edit Password Form
class EditPasswordForm(forms.ModelForm):
    """
    Form for editing password information.
    """
    class Meta:
        model = LoginRecord
        fields = ['password']
        labels = {'password': 'New Password'}
