"""Create and manage app models and methods."""

import uuid

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, \
                                        PermissionsMixin
                                        

from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.


class UserManager(BaseUserManager):
    """USER MANAGER CLASS GOING TO MANAGE OUR USER CLASS."""

    def create_user(self, email, password=None, **extra_fields):
        """Create_user method creates and saves new user objects."""
        if not email:
            raise ValueError('User must have valid email address')

        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password):
        """Create and saves a new super user."""
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True

        return user


class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model that supports using email instead of username."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=True)
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    
    def get_tokens(self):
        refresh = RefreshToken.for_user(self)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
