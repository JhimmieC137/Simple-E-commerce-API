from rest_framework import serializers

from core.models import User

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
        read_only_fields = ('email','is_active', 'is_staff',)


class CreateUserSerializer(serializers.ModelSerializer):      
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    name = serializers.CharField(required=True)
    
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
        

    class Meta:
        model = User
        fields = (
            'email',
            'password',
            'name',
        )
        extra_kwargs = {'password': {'write_only': True}}


class LoginUserSerializer(serializers.ModelSerializer):
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    class Meta:
        model = User
        fields = (
            'email',
            'password',
        )
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
    class Meta:
        model = User
        fields = (
            'password',
        )