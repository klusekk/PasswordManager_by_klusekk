from django.contrib.auth import authenticate, login, logout, update_session_auth_hash, get_user_model, authenticate
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm, AuthenticationForm
from django.urls import reverse_lazy
from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import FormView, TemplateView, CreateView, RedirectView
from django.http import HttpResponse, HttpResponseRedirect
from django.views.generic.edit import FormView, CreateView
from django.contrib.auth.hashers import make_password, check_password
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
from .models import AppVersion, LoginRecord, GeneratedLogin, MyAppUser



@method_decorator(login_required, name='dispatch')
class ChangeDataView(View):
    template_name = 'change_data.html'

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)
@method_decorator(login_required, name='dispatch')
class ChangePasswordView(View):
    template_name = 'change_pass.html'

    def get(self, request, *args, **kwargs):
        form = PasswordChangeForm(request.user)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Hasło zostało zmienione.')
            return redirect('/change_data')
        return render(request, self.template_name, {'form': form})

@method_decorator(login_required, name='dispatch')
class ChangeEmailView(View):
    template_name = 'change_mail.html'

    def get(self, request, *args, **kwargs):
        form = ChangeEmailForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = ChangeEmailForm(request.POST)
        if form.is_valid():
            request.user.email = form.cleaned_data['new_email']
            request.user.save()
            messages.success(request, 'Email został zmieniony.')
            return redirect('/change_data')
        return render(request, self.template_name, {'form': form})

@method_decorator(login_required, name='dispatch')
class ChangeDobView(View):
    template_name = 'change_dob.html'

    def get(self, request, *args, **kwargs):
        form = ChangeDOBForm(initial={'new_dob': request.user.birth_date})
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = ChangeDOBForm(request.POST)
        if form.is_valid():
            request.user.birth_date = form.cleaned_data['new_dob']
            request.user.save()
            return redirect('change_data')  # Przekieruj na inną stronę po zapisaniu zmian
        return render(request, self.template_name, {'form': form})

@method_decorator(login_required, name='dispatch')
class AccountDeleteView(View):
    template_name = 'acc_delete.html'

    def get(self, request, *args, **kwargs):
        form = DeleteAccountForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = DeleteAccountForm(request.POST)
        if form.is_valid():
            request.user.delete()
            messages.success(request, 'Twoje konto zostało usunięte. Zmiany są nieodwracalne.')
            return redirect('/home')
        return render(request, self.template_name, {'form': form})

class RedirectToHomeView(RedirectView):
    url = '/home/'

class LogoutView(TemplateView):
    template_name = 'logout.html'

    def post(self, request, *args, **kwargs):
        logout(request)
        return redirect(reverse_lazy('home'))

    def get_success_url(self):
        return reverse_lazy('dashboard')


logger = logging.getLogger(__name__)

class LoginView(FormView):
    template_name = 'login.html'
    form_class = AuthenticationForm
    success_url = reverse_lazy('dashboard')

    def form_valid(self, form):
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        # Logujemy próbę logowania
        logger.info(f"Próba logowania dla użytkownika: {username}")

        # Spróbuj uwierzytelnić użytkownika
        user = authenticate(username=username, password=password)

        if user is not None:
            # Udana autentykacja, logujemy
            login(self.request, user)
            return super().form_valid(form)
        else:
            # Nieudana autentykacja
            logger.warning(f"Nieudana próba logowania dla użytkownika: {username}")
            form.add_error(None, 'Błędne dane logowania')
            return self.form_invalid(form)

    def form_invalid(self, form):
        # Logujemy błędy formularza
        logger.warning(f"Błędy formularza logowania: {form.errors}")
        return super().form_invalid(form)


class HomeView(TemplateView):
    template_name = 'home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['app_name'] = 'Nazwa_apki'
        context['version'] = AppVersion.objects.first()  # Załóżmy, że masz tylko jedną wersję
        return context


class CreateUserView(FormView):
    template_name = 'create_user.html'
    form_class = CreateUserForm
    success_url = '/dashboard/'

    def form_valid(self, form):
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        email = form.cleaned_data['email']
        birth_date = form.cleaned_data['birth_date']

        # Sprawdź, czy użytkownik o podanej nazwie użytkownika już istnieje
        if MyAppUser.objects.filter(username=username).exists():
            form.add_error('username', 'Nazwa zajęta')
            return self.form_invalid(form)

        # Zaszyfruj hasło (możesz użyć bardziej zaawansowanego rozwiązania)
        hashed_password = make_password(password)

        # Sprawdź, czy użytkownik o podanym adresie email już istnieje
        if MyAppUser.objects.filter(email=email).exists():
            form.add_error('email', 'Email już zarejestrowany, przejdź do odzyskania hasła')
            return self.form_invalid(form)

        # Utwórz użytkownika
        user = MyAppUser.objects.create_user(username=username, email=email, birth_date=birth_date, password=password)

        # Zaloguj użytkownika po utworzeniu konta
        login(self.request, user)

        return super().form_valid(form)

class ForgotPasswordView(FormView):
    template_name = 'forgot_password.html'
    form_class = ForgotPasswordForm
    success_url = '/index/'

    def form_valid(self, form):
        # Wyślij instrukcje odzyskiwania hasła na podany adres email
        # ...

        return super().form_valid(form)

class AboutView(View):
    template_name = 'about.html'

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {'app_name': 'Manager Kont by klusekk'})

@method_decorator(login_required, name='dispatch')
class AddRecordView(TemplateView):
    template_name = 'add_record.html'


@method_decorator(login_required, name='dispatch')
class AddManualView(CreateView):
    model = LoginRecord
    form_class = AddManualForm
    template_name = 'add_manual.html'
    success_url = '/dashboard/'

    def form_valid(self, form):
        # Przypisz zalogowanego użytkownika do rekordu przed zapisaniem
        form.instance.user = self.request.user
        response = super().form_valid(form)
        return response

@method_decorator(login_required, name='dispatch')
class AddGenerateView(CreateView):
    model = GeneratedLogin
    form_class = AddGenerateForm
    template_name = 'add_generate.html'
    success_url = '/add_record/'

    def form_valid(self, form):
        user_instance = self.request.user  # Zmieniono ten fragment
        # Walidacja hasła
        password = self.generate_password(form.cleaned_data)
        form.instance.generated_password = password

        # Dodaj wygenerowany rekord do tabeli LoginRecord
        LoginRecord.objects.create(
            user=user_instance,
            page_name=form.cleaned_data['page_name'],
            category=form.cleaned_data['category'],
            login=form.cleaned_data['login'],
            password=password,
        )

        return super().form_valid(form)

    def generate_password(self, data):
        # Logika generowania hasła na podstawie formularza
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
    template_name = 'gen_pass.html'
    form_class = GeneratePasswordForm
    success_url = '/gen_pass/'

    def form_valid(self, form):
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
    template_name = 'dashboard.html'

    def get(self, request):
        return render(request, self.template_name)

@method_decorator(login_required, name='dispatch')
class SearchRecordView(View):
    template_name = 'search_for_record.html'

    def get(self, request, *args, **kwargs):
        query = self.request.GET.get('q', '')
        category = self.request.GET.get('category', '')

        # Jeśli zapytanie nie jest puste i ma minimum 3 znaki
        if len(query) >= 3:
            # Filtruj rekordy na podstawie kategorii (jeśli podana)
            if category:
                records = LoginRecord.objects.filter(page_name__icontains=query, category=category)
            else:
                records = LoginRecord.objects.filter(page_name__icontains=query)
        else:
            records = LoginRecord.objects.none()

        return render(request, self.template_name, {'query': query, 'category': category, 'records': records})

@method_decorator(login_required, name='dispatch')
class ShowPasswordView(DetailView):
    model = LoginRecord
    template_name = 'show_password.html'
    context_object_name = 'record'

    def post(self, request, *args, **kwargs):
        # Sprawdzanie daty urodzenia w profilu użytkownika (to wymaga dostosowania do twojego modelu użytkownika)
        user_birthdate = request.user.profile.birthdate  # Przykładowy dostęp do daty urodzenia w profilu użytkownika

        # Poniżej dodaj kod sprawdzający datę urodzenia i zwracający hasło
        input_birthdate = request.POST.get('birthdate', '')
        if input_birthdate == user_birthdate:
            return HttpResponse(self.object.password)
        else:
            return HttpResponse("Błędna data urodzenia. Hasło nie może zostać wyświetlone.")

@method_decorator(login_required, name='dispatch')
class DeleteRecordView(View):
    template_name = 'delete_record.html'

    def get(self, request, record_id):
        record = get_object_or_404(LoginRecord, pk=record_id)
        return render(request, self.template_name, {'record': record})

    def post(self, request, record_id):
        record = get_object_or_404(LoginRecord, pk=record_id)

        confirm_delete = request.POST.get('confirm_delete', '')
        if confirm_delete == 'Tak':
            record.delete()
        # Bez względu na wybór, przekieruj na stronę po usunięciu rekordu
        return HttpResponseRedirect('/search_for_record/')

@method_decorator(login_required, name='dispatch')
class EditLoginView(View):
    template_name = 'edit_record_login.html'

    def get(self, request, record_id):
        record = get_object_or_404(LoginRecord, pk=record_id)
        form = EditLoginForm(instance=record)
        return render(request, self.template_name, {'record': record, 'form': form})

    def post(self, request, record_id):
        record = get_object_or_404(LoginRecord, pk=record_id)
        form = EditLoginForm(request.POST, instance=record)

        if form.is_valid():
            form.save()
            return redirect('/search_for_record/')

        return render(request, self.template_name, {'record': record, 'form': form})

@method_decorator(login_required, name='dispatch')
class EditPasswordView(View):
    template_name = 'edit_record_pass.html'

    def get(self, request, record_id):
        record = get_object_or_404(LoginRecord, pk=record_id)
        form = EditPasswordForm(instance=record)
        return render(request, self.template_name, {'record': record, 'form': form})

    def post(self, request, record_id):
        record = get_object_or_404(LoginRecord, pk=record_id)
        form = EditPasswordForm(request.POST, instance=record)

        if form.is_valid():
            form.save()
            return redirect('/search_for_record/')

        return render(request, self.template_name, {'record': record, 'form': form})