# myapp/context_processors.py
import datetime
from django.conf import settings

def version_context(request):
    return {
        'version': getattr(settings, 'APP_VERSION', '1.0'),
        'current_datetime': datetime.datetime.now(),
    }