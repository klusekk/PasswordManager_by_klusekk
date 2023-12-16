from django.contrib.auth import authenticate, login, logout, update_session_auth_hash, get_user_model
from django.contrib.auth.forms import PasswordChangeForm, AuthenticationForm
from django.urls import reverse_lazy
from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import FormView, TemplateView, CreateView, RedirectView
from django.http import HttpResponse, HttpResponseRedirect
from django.views.generic.edit import FormView, CreateView
from django.contrib.auth.hashers import make_password
from django.views.generic.detail import DetailView
import logging
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views import View
from django.contrib import messages

from .forms import (
    LoginForm,
    CreateUserForm,
    ForgotPasswordForm,
    AddManualForm,
    AddGenerateForm,
    GeneratePasswordForm,
    ChangeEmailForm,
    ChangeDOBForm,
    DeleteAccountForm,
    EditLoginForm,
    EditPasswordForm,
)
from .models import LoginRecord, GeneratedLogin, MyAppUser


@method_decorator(login_required, name='dispatch')
class ChangeDataView(View):
    """
    A view for handling user data changes.
    """
    template_name = 'change_data.html'

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests and renders the change data page.
        """
        return render(request, self.template_name)


@method_decorator(login_required, name='dispatch')
class ChangePasswordView(View):
    """
    A view for handling password changes.
    """
    template_name = 'change_pass.html'

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests and renders the change password form.
        """
        form = PasswordChangeForm(request.user)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests and processes the password change form.
        """
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Password has been changed.')
            return redirect('/change_data')
        return render(request, self.template_name, {'form': form})


@method_decorator(login_required, name='dispatch')
class ChangeEmailView(View):
    """
    A view for handling email changes.
    """
    template_name = 'change_mail.html'

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests and renders the change email form.
        """
        form = ChangeEmailForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests and processes the change email form.
        """
        form = ChangeEmailForm(request.POST)
        if form.is_valid():
            request.user.email = form.cleaned_data['new_email']
            request.user.save()
            messages.success(request, 'Email has been changed.')
            return redirect('/change_data')
        return render(request, self.template_name, {'form': form})


@method_decorator(login_required, name='dispatch')
class ChangeDobView(View):
    """
    A view for handling date of birth changes.
    """
    template_name = 'change_dob.html'

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests and renders the change date of birth form.
        """
        form = ChangeDOBForm(initial={'new_dob': request.user.birth_date})
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests and processes the change date of birth form.
        """
        form = ChangeDOBForm(request.POST)
        if form.is_valid():
            request.user.birth_date = form.cleaned_data['new_dob']
            request.user.save()
            return redirect('change_data')  # Redirect to another page after saving changes
        return render(request, self.template_name, {'form': form})


@method_decorator(login_required, name='dispatch')
class AccountDeleteView(View):
    """
    A view for handling account deletion.
    """
    template_name = 'acc_delete.html'

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests and renders the account deletion form.
        """
        form = DeleteAccountForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests and processes the account deletion form.
        """
        form = DeleteAccountForm(request.POST)
        if form.is_valid():
            request.user.delete()
            messages.success(request, 'Your account has been deleted. Changes are irreversible.')
            return redirect('/home')
        return render(request, self.template_name, {'form': form})


class RedirectToHomeView(RedirectView):
    """
    A view for redirecting to the home page.
    """
    url = '/home/'


class LogoutView(TemplateView):
    """
    A view for handling user logout.
    """
    template_name = 'logout.html'

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests and logs the user out.
        """
        logout(request)
        return redirect(reverse_lazy('home'))

    def get_success_url(self):
        """
        Returns the success URL after logging out.
        """
        return reverse_lazy('dashboard')


logger = logging.getLogger(__name__)


class LoginView(FormView):
    """
    A view for handling user login.
    """
    template_name = 'login.html'
    form_class = AuthenticationForm
    success_url = reverse_lazy('dashboard')

    def form_valid(self, form):
        """
        Handles valid login form submissions.
        """
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        # Log login attempt
        logger.info(f"Login attempt for user: {username}")

        # Try to authenticate the user
        user = authenticate(username=username, password=password)

        if user is not None:
            # Successful authentication, log in
            login(self.request, user)
            return super().form_valid(form)
        else:
            # Unsuccessful authentication
            logger.warning(f"Failed login attempt for user: {username}")
            form.add_error(None, 'Invalid login credentials')
            return self.form_invalid(form)

    def form_invalid(self, form):
        """
        Handles invalid login form submissions.
        """
        # Log form errors
        logger.warning

class HomeView(TemplateView):
    """
    A view for rendering the home page.
    """
    template_name = 'home.html'

    def get_context_data(self, **kwargs):
        """
        Gets the context data for rendering the home page.
        """
        context = super().get_context_data(**kwargs)
        context['app_name'] = 'Password Manager by klusekk'
        return context


class CreateUserView(FormView):
    """
    A view for handling user registration.
    """
    template_name = 'create_user.html'
    form_class = CreateUserForm
    success_url = '/dashboard/'

    def form_valid(self, form):
        """
        Handles valid user registration form submissions.
        """
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        email = form.cleaned_data['email']
        birth_date = form.cleaned_data['birth_date']

        # Check if a user with the given username already exists
        if MyAppUser.objects.filter(username=username).exists():
            form.add_error('username', 'Username already taken')
            return self.form_invalid(form)

        # Encrypt the password (you may use a more advanced solution)
        hashed_password = make_password(password)

        # Check if a user with the given email already exists
        if MyAppUser.objects.filter(email=email).exists():
            form.add_error('email', 'Email already registered, proceed to password recovery')
            return self.form_invalid(form)

        # Create the user
        user = MyAppUser.objects.create_user(username=username, email=email, birth_date=birth_date, password=password)

        # Log in the user after account creation
        login(self.request, user)

        return super().form_valid(form)


class ForgotPasswordView(FormView):
    """
    A view for handling password recovery.
    """
    template_name = 'forgot_password.html'
    form_class = ForgotPasswordForm
    success_url = '/index/'

    def form_valid(self, form):
        """
        Handles valid password recovery form submissions.
        """
        # Send password recovery instructions to the provided email address
        # ...

        return super().form_valid(form)


class AboutView(View):
    """
    A view for rendering the about page.
    """
    template_name = 'about.html'

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests and renders the about page.
        """
        return render(request, self.template_name, {'app_name': 'Account Manager by klusekk'})


@method_decorator(login_required, name='dispatch')
class AddRecordView(TemplateView):
    """
    A view for rendering the add record page.
    """
    template_name = 'add_record.html'


@method_decorator(login_required, name='dispatch')
class AddManualView(CreateView):
    """
    A view for handling manual record creation.
    """
    model = LoginRecord
    form_class = AddManualForm
    template_name = 'add_manual.html'
    success_url = '/add_record/'

    def form_valid(self, form):
        """
        Handles valid manual record creation form submissions.
        """
        # Assign the logged-in user to the record before saving
        form.instance.user = self.request.user
        return super().form_valid(form)


@method_decorator(login_required, name='dispatch')
class AddGenerateView(CreateView):
    """
    A view for handling generated record creation.
    """
    model = GeneratedLogin
    form_class = AddGenerateForm
    template_name = 'add_generate.html'
    success_url = '/add_record/'

    def form_valid(self, form):
        """
        Handles valid generated record creation form submissions.
        """
        # Uzyskaj bieżącego użytkownika
        user_instance = self.request.user

        # Password validation
        password = self.generate_password(form.cleaned_data)
        form.instance.generated_password = password

        # Stwórz rekord GeneratedLogin przypisany do bieżącego użytkownika
        generated_login = form.save(commit=False)
        generated_login.user = user_instance
        generated_login.save()

        # Dodaj również rekord do LoginRecord
        LoginRecord.objects.create(
            user=user_instance,
            page_name=generated_login.page_name,
            category=generated_login.category,
            login=generated_login.login,
            password=password,
        )

        return redirect(self.success_url)

    def generate_password(self, data):
        """
        Generates a password based on the form data.
        """
        # Password generation logic based on the form
        min_length = data['min_password_length']
        require_uppercase = data['require_uppercase']
        require_lowercase = data['require_lowercase']
        require_special_characters = data['require_special_characters']

        generated_password = get_user_model().objects.make_random_password(
            length=min_length,
            allowed_chars=''.join([
                'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if require_uppercase else '',
                'abcdefghijklmnopqrstuvwxyz' if require_lowercase else '',
                '0123456789',
                '!@#$%^&*()_+{}|[]:;<>,.?/~`' if require_special_characters else '',
            ])
        )

        return generated_password


@method_decorator(login_required, name='dispatch')
class GeneratePasswordView(FormView):
    """
    A view for generating passwords based on user preferences.
    """
    template_name = 'gen_pass.html'
    form_class = GeneratePasswordForm
    success_url = '/gen_pass/'

    def form_valid(self, form):
        """
        Handles valid password generation form submissions.
        """
        user_model = get_user_model()
        generated_password = user_model.objects.make_random_password(
            length=form.cleaned_data['min_password_length'],
            allowed_chars=''.join([
                'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if form.cleaned_data['require_uppercase'] else '',
                'abcdefghijklmnopqrstuvwxyz' if form.cleaned_data['require_lowercase'] else '',
                '0123456789',
                '!@#$%^&*()_+{}|[]:;<>,.?/~`' if form.cleaned_data['require_special_characters'] else '',
            ])
        )
        form.cleaned_data['generated_password'] = generated_password
        self.request.session['generated_password'] = generated_password
        return super().form_valid(form)


@method_decorator(login_required, name='dispatch')
class DashboardView(View):
    """
    A view for rendering the user dashboard.
    """
    template_name = 'dashboard.html'

    def get(self, request):
        """
        Handles GET requests and renders the user dashboard.
        """
        return render(request, self.template_name)


@method_decorator(login_required, name='dispatch')
class SearchRecordView(View):
    """
    A view for searching user records.
    """
    template_name = 'search_for_record.html'

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests and renders the search record page.
        """
        query = self.request.GET.get('q', '')
        category = self.request.GET.get('category', '')

        # If the query is not empty and has a minimum length of 3 characters
        if len(query) >= 3:
            # Filter records based on the category (if provided)
            if category:
                records = LoginRecord.objects.filter(page_name__icontains=query, category=category)
            else:
                records = LoginRecord.objects.filter(page_name__icontains=query)
        else:
            records = LoginRecord.objects.none()

        return render(request, self.template_name, {'query': query, 'category': category, 'records': records})


@method_decorator(login_required, name='dispatch')
class ShowPasswordView(DetailView):
    """
    A view for displaying the password of a specific record.
    """
    model = LoginRecord
    template_name = 'show_password.html'
    context_object_name = 'record'

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for displaying the password.
        """
        # Check the user's birthdate in the user profile (this requires adjustment to your user model)
        user_birthdate = request.user.profile.birthdate  # Example access to the birthdate in the user profile

        # Add code below to check the birthdate and return the password
        input_birthdate = request.POST.get('birthdate', '')
        if input_birthdate == user_birthdate:
            return HttpResponse(self.object.password)
        else:
            return HttpResponse("Incorrect birthdate. The password cannot be displayed.")


@method_decorator(login_required, name='dispatch')
class DeleteRecordView(View):
    template_name = 'delete_record.html'

    def get(self, request, record_id):
        # Retrieve the record with the given ID or return a 404 response if not found
        record = get_object_or_404(LoginRecord, pk=record_id)
        return render(request, self.template_name, {'record': record})

    def post(self, request, record_id):
        # Retrieve the record with the given ID or return a 404 response if not found
        record = get_object_or_404(LoginRecord, pk=record_id)

        # Get the value of the confirm_delete field from the POST data
        confirm_delete = request.POST.get('confirm_delete', '')
        print(f"Confirm Delete: {confirm_delete}")

        if confirm_delete == 'Yes':
            # Delete the record if the user confirms the deletion
            print(f"Before Record Delete. Record ID: {record_id}, Login: {record.login}")
            record.delete()
            print(f"After Record Delete. Record ID: {record_id}, Login: {record.login}")

            # Redirect to the search_for_record page after successful deletion
            return HttpResponseRedirect(reverse('search_for_record'))
        else:
            # If the user does not confirm the deletion, provide feedback
            print("Record Not Deleted. Confirm Delete:", confirm_delete)

        # Provide a generic error message if something goes wrong
        return HttpResponse("Something went wrong. Record not deleted.")


@method_decorator(login_required, name='dispatch')
class EditLoginView(View):
    """
    A view for editing the login information of a user record.
    """
    template_name = 'edit_record_login.html'

    def get(self, request, record_id):
        """
        Handles GET requests for rendering the edit login information page.
        """
        record = get_object_or_404(LoginRecord, pk=record_id)
        form = EditLoginForm(instance=record)
        return render(request, self.template_name, {'record': record, 'form': form})

    def post(self, request, record_id):
        """
        Handles POST requests for editing the login information of a user record.
        """
        record = get_object_or_404(LoginRecord, pk=record_id)
        form = EditLoginForm(request.POST, instance=record)

        if form.is_valid():
            form.save()
            return redirect('/search_for_record/')

        return render(request, self.template_name, {'record': record, 'form': form})


@method_decorator(login_required, name='dispatch')
class EditPasswordView(View):
    """
    A view for editing the password of a user record.
    """
    template_name = 'edit_record_pass.html'

    def get(self, request, record_id):
        """
        Handles GET requests for rendering the edit password page.
        """
        record = get_object_or_404(LoginRecord, pk=record_id)
        form = EditPasswordForm(instance=record)
        return render(request, self.template_name, {'record': record, 'form': form})

    def post(self, request, record_id):
        """
        Handles POST requests for editing the password of a user record.
        """
        record = get_object_or_404(LoginRecord, pk=record_id)
        form = EditPasswordForm(request.POST, instance=record)

        if form.is_valid():
            form.save()
            return redirect('/search_for_record/')

        return render(request, self.template_name, {'record': record, 'form': form})
