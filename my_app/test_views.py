import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from mixer.backend.django import mixer  # Use mixer for model instances


pytestmark = pytest.mark.django_db

def test_show_password_view(client):
    user = mixer.blend(User)
    client.force_login(user)
    response = client.get(reverse('show_password', kwargs={'pk': 1}))
    assert response.status_code == 200

    response = client.post(reverse('show_password', kwargs={'pk': 1}), {'birthdate': '2023-01-01'})
    assert response.content == b"Incorrect birthdate. The password cannot be displayed."

def test_search_record_view(client):
    user = mixer.blend(User)
    client.force_login(user)
    response = client.get(reverse('search_for_record'))
    assert response.status_code == 200

def test_add_generate_view(client):
    user = mixer.blend(User)
    client.force_login(user)
    response = client.get(reverse('add_generate'))
    assert response.status_code == 200

    data = {
        'page_name': 'example_page',
        'category': 'example_category',
        'login': 'example_login',
        'min_password_length': 8,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_special_characters': True,
    }

    response = client.post(reverse('add_generate'), data)
    assert response.status_code == 302  # Redirect status code
    assert GeneratedLogin.objects.filter(user=user).exists()  # Check if a GeneratedLogin instance is created

    # Optional: Check if the associated LoginRecord is created as expected
    login_record = LoginRecord.objects.filter(user=user).first()
    assert login_record is not None
    assert login_record.page_name == 'example_page'
    assert login_record.category == 'example_category'
    assert login_record.login == 'example_login'
    assert len(login_record.password) == 8

