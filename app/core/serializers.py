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
            'email',
            'password',
            'name',
            'tokens',
        )
        read_only_fields = ('tokens',)
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