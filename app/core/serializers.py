from rest_framework import serializers

from core.models import *



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

        
class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model=Product
        fields = '__all__'
        extra_kwargs = {'category': {'write_only': True}}
    
    def create(self, validated_data):
        product = Product.objects.create(**validated_data)
        return product
    

class CategorySerializer(serializers.ModelSerializer):
    products = ProductSerializer(many=True, read_only=True)
    class Meta:
        model=Category
        fields = '__all__'
    
    def create(self, validated_data):
        category = Category.objects.create(**validated_data)
        return category
        
        
class OrderSerializer(serializers.ModelSerializer):
    products = ProductSerializer(many=True)
    class Meta:
        model=Order
        fields = '__all__'
class CreateOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model=Order
        fields = '__all__'
        read_only_fields = ('date_created', 'status')
    
    def create(self, validated_data):
        products = validated_data.pop('products')
        order = Order.objects.create(**validated_data)
        for product_id in products:
            order.products.add(product_id)
        
        return order
    
class UpdateOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model=Order
        fields = '__all__'
    
    def update(self, validated_data, *args, **kwargs):
        validated_data.date_updated = datetime.now()
        validated_data.save()
        return validated_data
        
class UserSerializer(serializers.ModelSerializer):
    orders = OrderSerializer(many=True, read_only=True)
    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'name',
            'orders',
            'is_staff',
            'is_active',
        )
        read_only_fields = ('email', 'is_active', 'is_staff',)