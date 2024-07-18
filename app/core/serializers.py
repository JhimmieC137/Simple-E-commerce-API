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