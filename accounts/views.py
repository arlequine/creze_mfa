from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from django_otp.oath import TOTP
from django_otp.util import random_hex
from django.contrib.auth import logout
import qrcode
from django.core.files.base import ContentFile
from io import BytesIO

import json

User = get_user_model()

@csrf_exempt
def register_view(request):
    print(request)
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data['username']
        password = data['password']

        user = User.objects.create_user(username=username, password=password)
        return JsonResponse({'status': 'User registered successfully'}, status=201)
    return JsonResponse({'error': 'Method not allowed'}, status=405)



@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data['username']
        password = data['password']
        otp_code = data.get('otp_code')

        user = authenticate(request, username=username, password=password)
        if user:
            if user.mfa_enabled:
                if otp_code:
                    totp = TOTP(user.mfa_secret)
                    if totp.verify(otp_code):
                        login(request, user)
                        return JsonResponse({'status': 'Login successful'}, status=200)
                    return JsonResponse({'error': 'Invalid OTP'}, status=401)
                return JsonResponse({'status': 'MFA_REQUIRED'}, status=401)
            login(request, user)
            return JsonResponse({'status': 'Login successful'}, status=200)
        return JsonResponse({'error': 'Invalid credentials'}, status=401)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def logout_view(request):
    logout(request)
    return JsonResponse({'status': 'Logged out successfully'}, status=200)



@csrf_exempt
def enable_mfa_view(request):
    user = request.user
    if request.method == 'POST':
        user.mfa_secret = random_hex(20)
        user.mfa_enabled = True
        user.save()
        
        totp = TOTP(user.mfa_secret)
        qr = qrcode.make(totp.provisioning_uri(user.username, issuer_name="Creze MFA"))
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        img_str = buffer.getvalue()
        
        return JsonResponse({'qr_code': img_str.hex()}, status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)