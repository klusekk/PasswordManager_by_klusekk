from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.generic import View, TemplateView, CreateView, FormView, DetailView
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponseRedirect, HttpResponse
from .models import LoginRecord, GeneratedLogin, MyAppUser, AppVersion
from .forms import (
    AddManualForm, AddGenerateForm, GeneratePasswordForm,
    EditLoginForm, EditPasswordForm, CreateUserForm, ForgotPasswordForm
)
from django.contrib.auth import get_user_model, authenticate, login, logout
import logging
from django.contrib.auth.forms import PasswordChangeForm

class ChangeDataViewTest(TestCase):
    def test_change_data_view_returns_200(self):
        # Test that the ChangeDataView returns a 200 status code
        response = self.client.get(reverse('change_data'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'change_data.html')

class ChangePasswordViewTest(TestCase):
    def setUp(self):
        # Create a user for testing
        self.user = User.objects.create_user(username='testuser', password='testpassword')

    def test_change_password_view_returns_200(self):
        # Test that the ChangePasswordView returns a 200 status code
        self.client.login(username='testuser', password='testpassword')
        response = self.client.get(reverse('change_pass'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'change_pass.html')

    def test_change_password_view_post_redirects_on_success(self):
        # Test that the ChangePasswordView redirects on successful password change
        self.client.login(username='testuser', password='testpassword')
        data = {'old_password': 'testpassword', 'new_password1': 'newtestpassword', 'new_password2': 'newtestpassword'}
        response = self.client.post(reverse('change_pass'), data)
        self.assertRedirects(response, reverse('change_data'))
        # Test that the user's password has been updated
        self.assertTrue(response.context['user'].check_password('newtestpassword'))

class ChangeEmailViewTest(TestCase):
    def setUp(self):
        # Create a user with an email address for testing
        self.user = User.objects.create_user(username='testuser', password='testpassword', email='test@example.com')

    def test_change_email_view_returns_200(self):
        # Test that the ChangeEmailView returns a 200 status code
        self.client.login(username='testuser', password='testpassword')
        response = self.client.get(reverse('change_mail'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'change_mail.html')

    def test_change_email_view_post_redirects_on_success(self):
        # Test that the ChangeEmailView redirects on successful email change
        self.client.login(username='testuser', password='testpassword')
        data = {'new_email': 'newtest@example.com'}
        response = self.client.post(reverse('change_mail'), data)
        self.assertRedirects(response, reverse('change_data'))
        # Test that the user's email address has been updated
        self.assertEqual(response.context['user'].email, 'newtest@example.com')


class ChangeDobViewTest(TestCase):
    def test_change_dob_view_returns_200(self):
        # Test that the ChangeDobView returns a 200 status code
        user = User.objects.create_user(username='testuser', password='testpassword', birth_date='2000-01-01')
        self.client.login(username='testuser', password='testpassword')
        response = self.client.get(reverse('change_dob'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'change_dob.html')

    def test_change_dob_view_post_redirects_on_success(self):
        # Test that the ChangeDobView redirects on successful date of birth change
        user = User.objects.create_user(username='testuser', password='testpassword', birth_date='2000-01-01')
        self.client.login(username='testuser', password='testpassword')
        data = {'new_dob': '1990-01-01'}
        response = self.client.post(reverse('change_dob'), data)
        self.assertRedirects(response, reverse('change_data'))
        # Test that the user's date of birth has been updated
        self.assertEqual(response.context['user'].birth_date, '1990-01-01')

class AccountDeleteViewTest(TestCase):
    def test_account_delete_view_returns_200(self):
        # Test that the AccountDeleteView returns a 200 status code
        user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        response = self.client.get(reverse('acc_delete'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'acc_delete.html')

    def test_account_delete_view_post_redirects_on_success(self):
        # Test that the AccountDeleteView redirects on successful account deletion
        user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {'confirmation': True}
        response = self.client.post(reverse('acc_delete'), data)
        self.assertRedirects(response, '/home')
        # Test that the user account has been deleted
        self.assertFalse(User.objects.filter(username='testuser').exists())

class RedirectToHomeViewTest(TestCase):
    def test_redirect_to_home_view_redirects_to_home(self):
        # Test that the RedirectToHomeView redirects to the home page
        response = self.client.get(reverse('redirect_to_home'))
        self.assertRedirects(response, '/home')


logger = logging.getLogger(__name__)

class LogoutViewTest(TestCase):
    def test_logout_view_redirects_on_post(self):
        # Test that the LogoutView redirects on a POST request
        user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        response = self.client.post(reverse('logout'))
        self.assertRedirects(response, reverse('home'))

class LoginViewTest(TestCase):
    def test_login_view_returns_200(self):
        # Test that the LoginView returns a 200 status code
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'login.html')

    def test_login_view_logs_successful_attempt(self):
        # Test that the LoginView logs a successful login attempt
        user = User.objects.create_user(username='testuser', password='testpassword')
        data = {'username': 'testuser', 'password': 'testpassword'}
        response = self.client.post(reverse('login'), data)
        # Check that the log entry is present
        self.assertIn('Login attempt for user: testuser', [record.getMessage() for record in logger.records])
        # Check that the user is logged in
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_login_view_logs_failed_attempt(self):
        # Test that the LoginView logs a failed login attempt
        data = {'username': 'nonexistentuser', 'password': 'wrongpassword'}
        response = self.client.post(reverse('login'), data)
        # Check that the log entry is present
        self.assertIn('Failed login attempt for user: nonexistentuser', [record.getMessage() for record in logger.records])
        # Check that the user is not logged in
        self.assertFalse(response.wsgi_request.user.is_authenticated)

class HomeViewTest(TestCase):
    def test_home_view_returns_200(self):
        # Test that the HomeView returns a 200 status code
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'home.html')

    def test_home_view_context_data(self):
        # Test that the HomeView provides the correct context data
        response = self.client.get(reverse('home'))
        self.assertEqual(response.context['app_name'], 'App_Name')
        # Assume AppVersion.objects.first() returns a version object
        self.assertEqual(response.context['version'], AppVersion.objects.first())


class CreateUserViewTest(TestCase):
    def test_create_user_view_returns_200(self):
        # Test that the CreateUserView returns a 200 status code
        response = self.client.get(reverse('create_user'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'create_user.html')

    def test_create_user_view_registers_user(self):
        # Test that the CreateUserView registers a user and logs them in
        data = {
            'username': 'testuser',
            'password': 'testpassword',
            'email': 'testuser@example.com',
            'birth_date': '2000-01-01'
        }
        response = self.client.post(reverse('create_user'), data)
        # Check that the user is redirected to the dashboard after successful registration
        self.assertRedirects(response, reverse('dashboard'))
        # Check that the user is logged in
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_create_user_view_duplicate_username(self):
        # Test that the CreateUserView handles duplicate usernames
        user = User.objects.create_user(username='existinguser', password='testpassword')
        data = {'username': 'existinguser', 'password': 'testpassword', 'email': 'newuser@example.com', 'birth_date': '2000-01-01'}
        response = self.client.post(reverse('create_user'), data)
        # Check that the form is invalid
        self.assertFormError(response, 'form', 'username', 'Username already taken')

    def test_create_user_view_duplicate_email(self):
        # Test that the CreateUserView handles duplicate email addresses
        user = User.objects.create_user(username='testuser', password='testpassword', email='existinguser@example.com')
        data = {'username': 'newuser', 'password': 'testpassword', 'email': 'existinguser@example.com', 'birth_date': '2000-01-01'}
        response = self.client.post(reverse('create_user'), data)
        # Check that the form is invalid
        self.assertFormError(response, 'form', 'email', 'Email already registered, proceed to password recovery')

class ForgotPasswordViewTest(TestCase):
    def test_forgot_password_view_returns_200(self):
        # Test that the ForgotPasswordView returns a 200 status code
        response = self.client.get(reverse('forgot_password'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'forgot_password.html')

    def test_forgot_password_view_sends_email(self):
        # Test that the ForgotPasswordView sends password recovery instructions
        # (Note: This test may require a custom email backend or other testing techniques)

class AboutViewTest(TestCase):
    def test_about_view_returns_200(self):
        # Test that the AboutView returns a 200 status code
        response = self.client.get(reverse('about'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'about.html')


@method_decorator(login_required, name='dispatch')
class AddRecordViewTest(TestCase):
    def test_add_record_view_returns_200(self):
        # Test that the AddRecordView returns a 200 status code
        response = self.client.get(reverse('add_record'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'add_record.html')

@method_decorator(login_required, name='dispatch')
class AddManualViewTest(TestCase):
    def test_add_manual_view_returns_200(self):
        # Test that the AddManualView returns a 200 status code
        response = self.client.get(reverse('add_manual'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'myapp/add_manual.html')

    def test_add_manual_view_creates_record(self):
        # Test that the AddManualView creates a manual login record
        user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {'page_name': 'Test Page', 'category': 'Test Category', 'login': 'testuser', 'password': 'testpassword'}
        response = self.client.post(reverse('add_manual'), data)
        # Check that the user is redirected to the dashboard after successful record creation
        self.assertRedirects(response, reverse('dashboard'))
        # Check that the manual login record is created
        self.assertTrue(LoginRecord.objects.filter(user=user, page_name='Test Page').exists())

@method_decorator(login_required, name='dispatch')
class AddGenerateViewTest(TestCase):
    def test_add_generate_view_returns_200(self):
        # Test that the AddGenerateView returns a 200 status code
        response = self.client.get(reverse('add_generate'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'myapp/add_generate.html')

    def test_add_generate_view_creates_record(self):
        # Test that the AddGenerateView creates a generated login record
        user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {
            'page_name': 'Test Page',
            'category': 'Test Category',
            'login': 'testuser',
            'min_password_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_special_characters': True
        }
        response = self.client.post(reverse('add_generate'), data)
        # Check that the user is redirected to the add record page after successful record creation
        self.assertRedirects(response, reverse('add_record'))
        # Check that the generated login record is created
        self.assertTrue(GeneratedLogin.objects.filter(user=user, page_name='Test Page').exists())

@method_decorator(login_required, name='dispatch')
class GeneratePasswordViewTest(TestCase):
    def test_generate_password_view_returns_200(self):
        # Test that the GeneratePasswordView returns a 200 status code
        response = self.client.get(reverse('gen_pass'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'gen_pass.html')

    def test_generate_password_view_generates_password(self):
        # Test that the GeneratePasswordView generates a password and stores it in the session
        data = {
            'min_password_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_special_characters': True
        }
        response = self.client.post(reverse('gen_pass'), data)
        # Check that the user is redirected to the password generation page after successful password generation
        self.assertRedirects(response, reverse('gen_pass'))
        # Check that the generated password is stored in the session
        self.assertIsNotNone(self.client.session.get('generated_password'))


@method_decorator(login_required, name='dispatch')
class DashboardViewTest(TestCase):
    def test_dashboard_view_returns_200(self):
        # Test that the DashboardView returns a 200 status code
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'dashboard.html')

@method_decorator(login_required, name='dispatch')
class SearchRecordViewTest(TestCase):
    def test_search_record_view_returns_200(self):
        # Test that the SearchRecordView returns a 200 status code
        response = self.client.get(reverse('search_for_record'))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'search_for_record.html')

    def test_search_record_view_displays_records(self):
        # Test that the SearchRecordView displays records based on the search query and category
        user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        data = {'q': 'Test', 'category': 'Test Category'}
        response = self.client.get(reverse('search_for_record'), data)
        # Check that the correct template is being used
        self.assertTemplateUsed(response, 'search_for_record.html')
        # Check that the record is present in the rendered page
        self.assertContains(response, 'Test Page')
        self.assertContains(response, 'testuser')

@method_decorator(login_required, name='dispatch')
class ShowPasswordViewTest(TestCase):
    def test_show_password_view_returns_200(self):
        # Test that the ShowPasswordView returns a 200 status code
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        response = self.client.get(reverse('show_password', kwargs={'pk': record.pk}))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'show_password.html')

    def test_show_password_view_displays_password_on_valid_post(self):
        # Test that the ShowPasswordView displays the password on a valid POST request
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {'birthdate': '1990-01-01'}  # Assuming the birthdate format is 'YYYY-MM-DD'
        response = self.client.post(reverse('show_password', kwargs={'pk': record.pk}), data)
        # Check that the password is displayed in the response content
        self.assertContains(response, 'testpassword')

    def test_show_password_view_returns_error_on_invalid_post(self):
        # Test that the ShowPasswordView returns an error message on an invalid POST request
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {'birthdate': '1990-01-02'}  # Invalid birthdate
        response = self.client.post(reverse('show_password', kwargs={'pk': record.pk}), data)
        # Check that the error message is displayed in the response content
        self.assertContains(response, 'Incorrect birthdate. The password cannot be displayed.')


@method_decorator(login_required, name='dispatch')
class DeleteRecordViewTest(TestCase):
    def test_delete_record_view_returns_200(self):
        # Test that the DeleteRecordView returns a 200 status code
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        response = self.client.get(reverse('delete_record', kwargs={'record_id': record.pk}))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'delete_record.html')

    def test_delete_record_view_deletes_record_on_confirm_yes(self):
        # Test that the DeleteRecordView deletes the record on 'confirm_delete' = 'Yes'
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {'confirm_delete': 'Yes'}
        response = self.client.post(reverse('delete_record', kwargs={'record_id': record.pk}), data)
        # Check that the record has been deleted
        self.assertEqual(LoginRecord.objects.filter(pk=record.pk).exists(), False)
        # Check that the response redirects to the correct URL
        self.assertRedirects(response, '/search_for_record/')

    def test_delete_record_view_does_not_delete_record_on_confirm_no(self):
        # Test that the DeleteRecordView does not delete the record on 'confirm_delete' = 'No'
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {'confirm_delete': 'No'}
        response = self.client.post(reverse('delete_record', kwargs={'record_id': record.pk}), data)
        # Check that the record still exists
        self.assertEqual(LoginRecord.objects.filter(pk=record.pk).exists(), True)
        # Check that the response redirects to the correct URL
        self.assertRedirects(response, '/search_for_record/')

@method_decorator(login_required, name='dispatch')
class EditLoginViewTest(TestCase):
    def test_edit_login_view_returns_200(self):
        # Test that the EditLoginView returns a 200 status code
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        response = self.client.get(reverse('edit_login', kwargs={'record_id': record.pk}))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'edit_record_login.html')

    def test_edit_login_view_edits_login_info_on_valid_post(self):
        # Test that the EditLoginView edits login information on a valid POST request
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {'page_name': 'Edited Page', 'category': 'Edited Category', 'login': 'editeduser'}
        response = self.client.post(reverse('edit_login', kwargs={'record_id': record.pk}), data)
        # Check that the login information has been edited
        edited_record = LoginRecord.objects.get(pk=record.pk)
        self.assertEqual(edited_record.page_name, 'Edited Page')
        self.assertEqual(edited_record.category, 'Edited Category')
        self.assertEqual(edited_record.login, 'editeduser')
        # Check that the response redirects to the correct URL
        self.assertRedirects(response, '/search_for_record/')

    def test_edit_login_view_does_not_edit_login_info_on_invalid_post(self):
        # Test that the EditLoginView does not edit login information on an invalid POST request
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {'page_name': '', 'category': '', 'login': ''}
        response = self.client.post(reverse('edit_login', kwargs={'record_id': record.pk}), data)
        # Check that the login information remains unchanged
        unchanged_record = LoginRecord.objects.get(pk=record.pk)
        self.assertEqual(unchanged_record.page_name, 'Test Page')
        self.assertEqual(unchanged_record.category, 'Test Category')
        self.assertEqual(unchanged_record.login, 'testuser')
        # Check that the response renders the correct template
        self.assertTemplateUsed(response, 'edit_record_login.html')

@method_decorator(login_required, name='dispatch')
class EditPasswordViewTest(TestCase):
    def test_edit_password_view_returns_200(self):
        # Test that the EditPasswordView returns a 200 status code
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        response = self.client.get(reverse('edit_password', kwargs={'record_id': record.pk}))
        self.assertEqual(response.status_code, 200)
        # Test that the correct template is being used
        self.assertTemplateUsed(response, 'edit_record_pass.html')

    def test_edit_password_view_edits_password_on_valid_post(self):
        # Test that the EditPasswordView edits the password on a valid POST request
        user = User.objects.create_user(username='testuser', password='testpassword')
        record = LoginRecord.objects.create(user=user, page_name='Test Page', category='Test Category', login='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        data = {'password': 'newtestpassword'}
        response = self.client.post(reverse('edit_password', kwargs={'record_id': record.pk}), data)
        # Check that the password has been edited
        edited_record = LoginRecord.objects.get(pk=record.pk)
        self.assertEqual(edited_record.password, 'newtestpassword')
        # Check that the response redirects to the correct
