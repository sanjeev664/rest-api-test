# from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from rest_framework import serializers
# from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError, AccessToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework.validators import UniqueValidator
from django.contrib.auth.hashers import make_password
from django.utils.translation import gettext_lazy as _


User = get_user_model()
# Serializers define the API representation.
class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = [ 
            "email", 
            "country", 
            "city", 
            "email", 
            "gender"
        ]

class AuthTokenLoginSerializer(serializers.Serializer):
    email = serializers.CharField(
        label=_("Username"),
        write_only=True
    )
    password = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )
    token = serializers.CharField(
        label=_("Token"),
        read_only=True
    )

    class Meta:
        model = User
        fields = [
            "username", 
            "email", 
            "country", 
            "city", 
            "email", 
            "password", 
            "password2", 
            "gender",
            ]

    def validate(self, attrs):
        username = attrs.get('email')
        password = attrs.get('password')

        if username and password:
            obj = User.objects.filter(email=username).first()
            if obj:
                if obj.is_active == False:
                    raise serializers.ValidationError({"message": "Your Email is not confirm !!"})
            user = authenticate(request=self.context.get('request'),
                                username=username, password=password)

            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)
            if not user:
                msg = _('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs

class RegisterSerializer(serializers.ModelSerializer):

    # email = serializers.EmailField(
    #     required=True, 
    #     validators=[UniqueValidator(queryset=User.objects.all())]
    #     )

    password = serializers.CharField(
        write_only=True,
        required=True
        )

    password2 = serializers.CharField(
        write_only=True,
        required=True
    )

    default_error_messages = {
        'username': 'The username should only contain alphanumeric characters'}

    class Meta:
        model = User
        fields = [
            "first_name", 
            "last_name", 
            "username", 
            "email", 
            "country", 
            "city", 
            "password", 
            "password2", 
            "gender",
            ]

    def validate(self, attrs):
        email = attrs.get('email', '')

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "This Email is already exists!!"})

        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match !!"})
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            first_name = validated_data['first_name'],
            last_name = validated_data['last_name'],
            country = validated_data['country'],
            city = validated_data['city'],
            email = validated_data['email'],
            password = make_password(validated_data['password'])
        )
        user.save()
        return user
        