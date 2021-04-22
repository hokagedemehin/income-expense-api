from django.shortcuts import render
from rest_framework import generics, status, views
from .serializers import *
from .models import *
from .utils import *
from django.urls import reverse
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site

import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer

from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Create your views here.

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token=RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse("email-verify")
        # data = {'domain': current_site.domain }
        absurl = f"http://{current_site}{relativeLink}?token={str(token)}"
        email_body = f"Hello {user.username} \n\n"f"Please use the below link to verify your email \n\n"f"{absurl}"
        data = {'email_body': email_body,"email_to": user.email, "email_subject": "Please Verify Your Email" }
        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED )

class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token',in_=openapi.IN_QUERY,description='Enter your token here',type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request): 
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            # print(payload)
            user = User.objects.get(id=payload['user_id'])
            # print(user)
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated your account'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation link is expired'}, status=status.HTTP_400_BAD_REQUEST)
        except  jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status = status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = RequestPasswordResetEmailSerializer
    def post(self, request):
        # data = {'request': request, 'data': request.data}
        serializer = self.serializer_class(data=request.data)
        email = request.data["email"]
        # serializer.is_valid(raise_exception=True)
        if User.objects.filter(email = email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse("password-reset-confirm", kwargs={'uidb64': uidb64, 'token': token})
            # data = {'domain': current_site.domain }
            absurl = f"http://{current_site}{relativeLink}"
            email_body = f"Hello, \n\n"f"Please use the below link to reset your password \n\n"f"{absurl}"
            data = {'email_body': email_body,"email_to": user.email, "email_subject": "Please Reset Your Password" }
            Util.send_email(data)
        return Response({"success": "We have sent you a link to reset your password"}, status = status.HTTP_200_OK)

class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({"error": "Token not valid anymore, please request a new one"}, status=status.HTTP_401_UNAUTHORIZED)
        
            return Response({"success": True, "message": "Credentials is valid", "uidb64": uidb64, "token": token}, status = status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({"error": "Token not valid anymore, please request a new one"}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordAPIViewSerializer
    
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"success": True, "message": "Password reset success"}, status = status.HTTP_200_OK)
