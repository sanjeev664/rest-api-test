from django.contrib import admin
from django.contrib.auth import get_user_model
# from .models import User
from django.contrib.auth.models import Group

# Register your models here.

AdminUser = get_user_model()
admin.site.register(AdminUser)