import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from authentication.cognito import helpers
from authentication.cognito.base import CognitoException


@csrf_exempt
@require_http_methods(['POST'])
def initiate_auth(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        result = helpers.initiate_auth(data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)


@require_http_methods(['POST'])
def respond_to_auth_challenge(request):
    try:
        result = helpers.respond_to_auth_challenge(request.data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)
    pass


@require_http_methods(['POST'])
def forgot_password(request):
    try:
        result = helpers.forgot_password(request.data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)
    pass


@require_http_methods(['POST'])
def confirm_forgot_password(request):
    try:
        result = helpers.confirm_forgot_password(request.data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)
    pass


@require_http_methods(['POST'])
def sign_up(request):
    try:
        result = helpers.sign_up(request.data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)
    pass


@require_http_methods(['POST'])
def confirm_sign_up(request):
    try:
        result = helpers.confirm_sign_up(request.data)

        return JsonResponse(result, status=200)
    except CognitoException as ex:
        return JsonResponse(ex.message, ex.status)
    pass
