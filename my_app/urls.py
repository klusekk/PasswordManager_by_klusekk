from django.urls import path
from django.contrib.auth.decorators import login_required
from .views import (
    LoginView,
    ForgotPasswordView,
    HomeView,
    CreateUserView,
    AboutView,
    AddRecordView,
    AddManualView,
    AddGenerateView,
    GeneratePasswordView,
    ChangeDataView,
    ChangePasswordView,
    ChangeEmailView,
    ChangeDobView,
    AccountDeleteView,
    LogoutView,
    RedirectToHomeView,
    DashboardView,
    SearchRecordView,
    ShowPasswordView,
    EditLoginView,
    EditPasswordView,
    DeleteRecordView
)

urlpatterns = [
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('', RedirectToHomeView.as_view(), name='redirect_to_home'),
    path('login/', LoginView.as_view(), name='login'),
    path('forgot_password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('home/', HomeView.as_view(), name='home'),
    path('create_user/', CreateUserView.as_view(), name='create_user'),
    path('about/', AboutView.as_view(), name='about'),
    path('add_record/', AddRecordView.as_view(), name='add_record'),
    path('add_manual/', AddManualView.as_view(), name='add_manual'),
    path('add_generate/', AddGenerateView.as_view(), name='add_generate'),
    path('gen_pass/', GeneratePasswordView.as_view(), name='gen_pass'),
    path('change_data/', ChangeDataView.as_view(), name='change_data'),
    path('change_password/', ChangePasswordView.as_view(), name='change_pass'),
    path('change_mail/', ChangeEmailView.as_view(), name='change_mail'),
    path('change_dob/', ChangeDobView.as_view(), name='change_dob'),
    path('acc_delete/', AccountDeleteView.as_view(), name='acc_delete'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('search_for_record/', SearchRecordView.as_view(), name='search_for_record'),
    path('show_password/<int:pk>/', ShowPasswordView.as_view(), name='show_password'),
    path('edit_login/<int:record_id>/', EditLoginView.as_view(), name='edit_login'),
    path('edit_password/<int:record_id>/', EditPasswordView.as_view(), name='edit_password'),
    path('delete_record/<int:record_id>/', DeleteRecordView.as_view(), name='delete_record'),

]


