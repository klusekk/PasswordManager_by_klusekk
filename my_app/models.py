from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

class AppVersion(models.Model):
    version_number = "0.1.6"
    release_date = "08/12/2023"

    def __str__(self):
        return self.version_number


class MyAppUserManager(BaseUserManager):
    def create_user(self, email, birth_date, username=None, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, birth_date=birth_date, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, birth_date, username=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, birth_date, username, password, **extra_fields)


class MyAppUser(AbstractUser):
    birth_date = models.DateField()

    REQUIRED_FIELDS = ['email', 'birth_date']
    USERNAME_FIELD = 'username'

    def __str__(self):
        return self.username


class LoginRecord(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(MyAppUser, on_delete=models.CASCADE, related_name='login_records', default='admin')
    page_name = models.CharField(max_length=255)
    category = models.CharField(max_length=50)
    login = models.CharField(max_length=100)
    password = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.page_name} - {self.login}"

class GeneratedLogin(models.Model):
    page_name = models.CharField(max_length=100)
    category = models.CharField(max_length=50)
    login = models.CharField(max_length=50)
    generated_password = models.CharField(max_length=50)

    def __str__(self):
        return self.page_name
