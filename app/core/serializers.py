from django.contrib.auth import login, logout, authenticate

from rest_framework import serializers

from core.models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'name',
            'is_staff',
            'is_active',
        )
        read_only_fields = ('email', 'is_active', 'is_staff',)


class CreateUserSerializer(serializers.ModelSerializer):
    tokens = serializers.SerializerMethodField()
    
    def get_tokens(self, user):
        return user.get_tokens()
    
    def create(self, validated_data):
        # Keep all email addresses unique by converting them to lower case
        validated_data['email'] = validated_data['email'].lower() 
        user = User.objects.create_user(**validated_data)
        return user
        

    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'name',
            'password',
            'tokens',
            'is_staff',
            'is_active',
        )
        read_only_fields = ('id', 'tokens', 'is_staff', 'is_active')
        extra_kwargs = {'password': {'write_only': True}}


class LoginUserSerializer(serializers.ModelSerializer):
    tokens = serializers.SerializerMethodField()
    
    def get_tokens(self, user):
        return user.get_tokens()        
        ...
    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'name',
            'password',
            'tokens',
            'is_staff',
            'is_active',
        )
        read_only_fields = ('id', 'tokens', 'name', 'is_staff', 'is_active')
        extra_kwargs = {'password': {'write_only': True}}

class UpdateUserSerializer(serializers.ModelSerializer):   
    class Meta:
        model = User
        fields = (
            'email',
            'name',
        )

class RequestPasswordResetSerializer(serializers.ModelSerializer):   
    class Meta:
        model = User
        fields = (
            'email',
        )

class ResetPasswordSerializer(serializers.ModelSerializer):
    tokens = serializers.SerializerMethodField()
    
    def get_tokens(self, user):
        return user.get_tokens()    
    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'name',
            'tokens',
            'is_staff',
            'is_active',
        )
        read_only_fields = ('id', 'email', 'tokens', 'name', 'is_staff', 'is_active')
        
        
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model=Category
        fields = '__all__'
    
    def create(self, validated_data):
        category = Category.objects.create(**validated_data)
        return category
