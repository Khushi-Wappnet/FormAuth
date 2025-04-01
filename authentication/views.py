from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import CustomUser, OTP
from .forms import RegistrationForm, OTPVerificationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import random


def send_otp(user):
    otp_code = str(random.randint(100000, 999999))
    OTP.objects.create(user=user, otp_code=otp_code)
    send_mail(
        'Your OTP Code',
        f'Your OTP code is {otp_code}',
        'noreply@example.com',
        [user.email],
        fail_silently=False,
    )


class RegisterView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
                'username': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_PASSWORD),
                'mobile_number': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['first_name', 'last_name', 'email', 'username', 'password', 'mobile_number']
        )
    )
    def post(self, request):
        form = RegistrationForm(request.data)  # ✅ Remove .dict()
        
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            send_otp(user)
            return Response({'message': 'User registered successfully. OTP sent to email.'}, status=status.HTTP_201_CREATED)
        
        return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)



class VerifyOTPView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
                'otp_code': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['email', 'otp_code']
        )
    )
    def post(self, request):
        form = OTPVerificationForm(request.data)
        if form.is_valid():
            try:
                user = CustomUser.objects.get(email=form.cleaned_data['email'])
                otp = OTP.objects.filter(user=user, otp_code=form.cleaned_data['otp_code']).first()
                if otp and otp.is_valid():  # This now works because is_valid is defined
                    user.is_email_verified = True
                    user.save()
                    otp.delete()
                    return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
                elif otp:
                    otp.delete()  # Delete expired OTP
                    return Response({'error': 'OTP expired.'}, status=status.HTTP_400_BAD_REQUEST)
                return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
            except CustomUser.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
                'password': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_PASSWORD),
            },
            required=['email', 'password']
        )
    )
    def post(self, request):
        form = LoginForm(request.data)
        if form.is_valid():
            try:
                user = CustomUser.objects.get(email=form.cleaned_data['email'])
                if not user.is_email_verified:
                    send_otp(user)
                    return Response({'message': 'Email not verified. OTP sent to email.'}, status=status.HTTP_403_FORBIDDEN)
                if user.check_password(form.cleaned_data['password']):
                    tokens = self.generate_tokens_for_user(user)
                    return Response({'message': 'Login successful.', 'tokens': tokens}, status=status.HTTP_200_OK)
                return Response({'error': 'Invalid credentials.'}, status=status.HTTP_400_BAD_REQUEST)
            except CustomUser.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)

    def generate_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }


class ForgotPasswordView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
            },
            required=['email']
        )
    )
    def post(self, request):
        form = ForgotPasswordForm(request.data)
        if form.is_valid():
            try:
                user = CustomUser.objects.get(email=form.cleaned_data['email'])
                send_otp(user)
                return Response({'message': 'OTP sent to email.'}, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
                'otp_code': openapi.Schema(type=openapi.TYPE_STRING),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_PASSWORD),
            },
            required=['email', 'otp_code', 'new_password']
        )
    )
    def post(self, request):
        form = ResetPasswordForm(request.data)
        if form.is_valid():
            try:
                user = CustomUser.objects.get(email=form.cleaned_data['email'])
                otp = OTP.objects.filter(user=user, otp_code=form.cleaned_data['otp_code']).first()
                if otp and otp.is_valid():
                    user.set_password(form.cleaned_data['new_password'])
                    user.save()
                    otp.delete()
                    return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
                elif otp:
                    otp.delete()
                    return Response({'error': 'OTP expired.'}, status=status.HTTP_400_BAD_REQUEST)
                return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
            except CustomUser.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)
