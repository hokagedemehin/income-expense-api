from rest_framework import serializers
from .models import *
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import *


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    # message = serializers.SerializerMethodField(read_only=True)
    class Meta:
        model = User
        fields = ['email', 'username', 'password']
    
    # def get_message(self, obj):
    #     return f"Check your email for a link to verification link"

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError('The username should only contain alphanumeric characters')
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=600)

    class Meta:
        model = User
        fields = ['token']

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=68, min_length=1, read_only=True)
    tokens = serializers.CharField(max_length=600, min_length=1, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password)
        # import pdb
        # pdb.set_trace()
        if not user:
            raise AuthenticationFailed('Invalid credentials, please try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Account is not verified, please check the link sent to your email')
        
        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens(),
        }
        return super().validate(attrs)

class RequestPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        model = User
        fields = ['email']
    
    def validate(self, attrs):
        email = attrs['data'].get('email', '')
        if User.objects.filter(email = email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(user.id)
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=attrs['data'].get('request')).domain
            relativeLink = reverse("password-reset-confirm", kwargs={'uidb64': uidb64, 'token': token})
            # data = {'domain': current_site.domain }
            absurl = f"http://{current_site}{relativeLink}"
            email_body = f"Hello, \n\n"f"Please use the below link to reset your password \n\n"f"{absurl}"
            data = {'email_body': email_body,"email_to": user.email, "email_subject": "Please Reset Your Password" }
            Util.send_email(data)
            # return attrs
        return super().validate(attrs)

class SetNewPasswordAPIViewSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        models = User
        fields = ['password', 'token', 'uidb64']
    
    def validate(self, attrs):
        try:
            password = attrs.get("password")
            token = attrs.get("token")
            uidb64 = attrs.get("uidb64")

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("The reset link is invalid", 401)
            
            user.set_password(password)
            user.save()
        except Exception as e:
            raise AuthenticationFailed("The reset link is invalid", 401)

        return super().validate(attrs)