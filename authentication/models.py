from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.utils.translation import ugettext_lazy as _
# from django.contrib.auth.base_user import BaseUserManager

from django.template.loader import render_to_string
from django.utils.html import strip_tags

from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.
# from django.contrib.auth.models import (
#     AbstractBaseUser, BaseUserManager, PermissionsMixin)


class UserManager(BaseUserManager):

    def create_user(self, email, password=None):
        """Create and return a `User` with an email, username and password."""
        # if username is None:
        #     raise TypeError('Users must have a username.')

        if email is None:
            raise TypeError('Users must have an email address.')

        user = self.model(email=self.normalize_email(email))
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, email, password):
        """
        Create and return a `User` with superuser (admin) permissions.
        """
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(email, password)
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.save()
        return user


class User(AbstractUser):
    GENDER_CHOICES = (
        ('M', 'Male'),
        ('F', 'Female'),
    )
    username = None
    name = models.CharField(_("Name"), max_length=100)
    email = models.EmailField(_('email address'), unique=True)
    country = models.CharField(_("Country Name"), max_length=100, null=True, blank=True)
    city = models.CharField(_("City Name"), max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)

    USERNAME_FIELD = 'email' 
    REQUIRED_FIELDS = []

    objects =  UserManager()

    def __str__(self):
        return self.email

    # Token method 
    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }
