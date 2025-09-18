from django.contrib.auth.models import AbstractBaseUser ,PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _
from .managers import CustomUserManager

class CustomUser(AbstractBaseUser  ,PermissionsMixin):
    username = models.CharField( max_length=50)
    email = models.EmailField(unique=True)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    

    objects = CustomUserManager()

    def __str__(self):
        return self.email
