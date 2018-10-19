import datetime
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.models import User
import json
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

