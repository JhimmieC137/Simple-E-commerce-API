import jwt
from datetime import datetime, timedelta

# Django Iports
from django.contrib.auth import login, logout, authenticate
from django.core.exceptions import ValidationError
from django.db.models import Q


# DRF Imports
from rest_framework import viewsets, mixins
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken

# Core Iports
from app.settings import SECRET_KEY
from core.models import *
from core.serializers import *



##########################
#  AUTH
##########################
class AuthViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    # parser_classes = (MultiPartParser, FormParser)
    queryset = User.objects.all()
    serializers = {
        'default': UserSerializer,
        'create': CreateUserSerializer,
        'login_view': LoginUserSerializer,
        'reset_password': ResetPasswordSerializer,
        'request_password_reset': RequestPasswordResetSerializer,
    }

    
    def get_queryset(self):                                      
        return super().get_queryset()
    
    def get_serializer_class(self):
        return self.serializers.get(self.action, self.serializers['default'])
    
    @action(detail=False, methods=['get'], url_path='me', url_name='me')
    def session(self, instance):
        """
        User in session
        """
        try:
            return Response(UserSerializer(self.request.user, context={'request': self.request}).data, status=status.HTTP_200_OK)
        except:
            return Response({'message': 'Wrong auth token'}, status=status.HTTP_400_BAD_REQUEST)
        
        
    def create(self, request):
        """
        User registeration
        """
        try:
            user = self.queryset.filter(email = request.data['email'].lower()).exists()
            if user:
                return Response({'message': 'Email already exists'}, status=status.HTTP_409_CONFLICT)
                
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({"message": "User created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            return Response({'message': 'Something went wrong'}, status=status.HTTP_400_BAD_REQUEST)
        
        
    @action(detail=False, methods = ['post'], url_path='login', url_name='login')
    def login_view(self, request):
        """
        User login 
        """
        try:
            user = self.queryset.get(email = request.data['email'].lower())
            if user:
                if  user.is_active:
                    user = authenticate(email=request.data['email'].lower(), password=request.data['password'])
                    if user:    
                        serializer = self.get_serializer(user, data=request.data)
                        serializer.is_valid(raise_exception=True)
                        return Response({'mesesage':'Logged in successfully', 'data': serializer.data}, status=status.HTTP_200_OK)
                    else:
                        return Response({'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({'message': 'User has been dactivated'}, status=status.HTTP_403_FORBIDDEN)
            else:
                return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            return Response({'message': f'Something went wrong {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    
    @action(detail=False, methods = ['post'], url_path='request-password-reset', url_name='request-password-reset')
    def request_password_reset(self, request):
        """
        Send password reset link via email 
        """
        try:
            user = self.queryset.get(email = request.data['email'].lower())
            if user:
                if  user.is_active:
                    # Append token to FE url as a query parameter
                    reset_token = jwt.encode({'id': user.id, 'exp': datetime.now() + timedelta(minutes=10)}, SECRET_KEY, algorithm="HS256")
                    
                    # Token is being returned for the purpose of testing the endpoint 
                    return Response({'message': 'Reset mail sent', 'data': reset_token}, status=status.HTTP_200_OK)
                else:
                    return Response({'message': 'User has been dactivated'}, status=status.HTTP_403_FORBIDDEN)
                
            else:
                return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except:
            return Response({'message': 'Something went wrong'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    @action(detail=False, methods = ['post'], url_path='reset-password', url_name='reset-password')
    def reset_password(self, request):
        """
        Password reset
        """        
        try:
            payload: dict = jwt.decode(str(request.headers['authorization']).split(' ')[1], SECRET_KEY, algorithms=["HS256"])
        except:
            return Response({'message': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = self.queryset.get(id = payload['id'])    
            if user:
                if  user.is_active:
                    user.set_password(request.data['password'])
                    user.save()
                    serializer = self.get_serializer(user, data=request.data)
                    serializer.is_valid(raise_exception=True)
                    return Response({'message': 'Password reset successful', 'data': serializer.data}, status=status.HTTP_200_OK)
                
                else:
                    return Response({'message': 'User has been dactivated'}, status=status.HTTP_403_FORBIDDEN)
                
            else:
                return Response(f"User not found", status=status.HTTP_404_NOT_FOUND)
        except:
            return Response({'message': 'Something went wrong'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    @action(detail=False, methods = ['get'], url_path='logout', url_name='logout')
    def logout_view(self, request):
        """
        Remove user from session
        """
        try:
            if str(request.headers['authorization']) is None or str(request.headers['authorization']) == "":
                return Response({'messgae': 'No token detected'}, status=status.HTTP_200_OK)
                
            token = RefreshToken(str(request.headers['authorization']).split(' ')[1])
            token.blacklist()
            logout(request)
            return Response({'messgae': 'Logged out successfully'}, status=status.HTTP_200_OK)
        except:
            return Response({'messgae': 'Something went wrong'}, status=status.HTTP_200_OK)



##########################
#  USER
##########################
class UserViewSet(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """
    Creates, Updates and Retrieves - User Accounts
    """
    # parser_classes = (MultiPartParser, FormParser)
    queryset = User.objects.all()
    serializers = {
        'default': UserSerializer,
    }
    
    def get_queryset(self):                                      
        return super().get_queryset()
    
    def get_serializer_class(self):
        return self.serializers.get(self.action, self.serializers['default'])
    
    def list(self, request):
        queryset = self.get_queryset()
        queryset = self.queryset.filter(
            Q(name__icontains = request.query_params.get('search') if request.query_params.get('search') else '') |
            Q(email__icontains = request.query_params.get('search') if request.query_params.get('search') else ''),
            is_active = True
        ).values()
        try:
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                paginated_response = self.get_paginated_response(serializer.data)
                paginated_response.data['message'] = "Users retrived successfully"
                return paginated_response

        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
        except:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            if instance.is_active:
                serializer = self.get_serializer(instance)
                return Response({"message":"User retrived successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
            else:
                return Response({'message': 'User has been dactivated'}, status=status.HTTP_403_FORBIDDEN)
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
    def perform_update(self, serializer):
        serializer.save()
        
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        try:
            instance = self.get_object()
        except:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            if instance.is_active:
                serializer = self.get_serializer(instance, data=request.data, partial=partial)
                serializer.is_valid(raise_exception=True)
                self.perform_update(serializer)
                return Response({"message": "User updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'User has been dactivated'}, status=status.HTTP_403_FORBIDDEN)
                    
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
      

##########################
#  CATEGORY
##########################
class CategoryViewSet(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, mixins.CreateModelMixin, mixins.DestroyModelMixin, viewsets.GenericViewSet):
    queryset = Category.objects.all()
    serializers = {
        'default': CategorySerializer,
    }
    
    def get_queryset(self):                                      
        return super().get_queryset()
    
    def get_serializer_class(self):
        return self.serializers.get(self.action, self.serializers['default'])
    
    def list(self, request):
        """
        Create category
        """
        queryset = self.get_queryset()
        queryset = self.queryset.filter(
            Q(name__icontains = request.query_params.get('search') if request.query_params.get('search') else '')
        ).values()
        try:
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                paginated_response = self.get_paginated_response(serializer.data)
                paginated_response.data['message'] = "Categories retrived successfully"
                return paginated_response
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def create(self, request):
        """
        Create category
        """
        try:
            category = self.queryset.filter(name = request.data['name']).exists()
            if category:
                return Response({'message': 'Category already exists'}, status=status.HTTP_409_CONFLICT)
                
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({"message": "Category created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            return Response({'message': 'Something went wrong'}, status=status.HTTP_400_BAD_REQUEST)
        
        
    def retrieve(self, request, *args, **kwargs):
        """
        Get category
        """
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            serializer = self.get_serializer(instance)
            return Response({"message":"Category retrived successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def update(self, request, *args, **kwargs):
        """
        Update category
        """
        partial = kwargs.pop('partial', False)
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"message": "Category updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    def destroy(self, request, *args, **Kwargs):
        """
        Delete category
        """
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            instance = self.get_object()
            instance.delete()
            return Response({"message":"Category deleted successfully"}, status=status.HTTP_200_OK)
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


##########################
#  PRODUCT
##########################
class ProductViewSet(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, mixins.CreateModelMixin, mixins.DestroyModelMixin, viewsets.GenericViewSet):
    queryset = Product.objects.all()
    serializers = {
        'default': ProductSerializer,
    }
    
    def get_queryset(self):                                      
        return super().get_queryset()

    def get_serializer_class(self):
        return self.serializers.get(self.action, self.serializers['default'])

    def list(self, request):
        """
        Create product
        """
        queryset = self.get_queryset()
        queryset = self.queryset.filter(
            Q(name__icontains = request.query_params.get('search') if request.query_params.get('search') else '')
        ).values()
        try:
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                paginated_response = self.get_paginated_response(serializer.data)
                paginated_response.data['message'] = "Products retrived successfully"
                return paginated_response
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    def create(self, request):
        """
        Create product
        """        
        try:
            category = self.queryset.filter(name = request.data['category']).exists()
            if not category:
                return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)
            
            product = self.queryset.filter(name = request.data['name']).exists()
            if product:
                return Response({'message': 'Product already exists'}, status=status.HTTP_409_CONFLICT)
            
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({"message": "Product created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        
        except:
            return Response({'message': 'Something went wrong'}, status=status.HTTP_400_BAD_REQUEST)
        
        
    def retrieve(self, request, *args, **kwargs):
        """
        Get product
        """
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            serializer = self.get_serializer(instance)
            return Response({"message":"Product retrived successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def update(self, request, *args, **kwargs):
        """
        Update product
        """
        partial = kwargs.pop('partial', False)
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            category = Category.objects.filter(id = request.data['category']).exists()
            if not category:
                return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"message": "Product updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    def destroy(self, request, *args, **Kwargs):
        """
        Delete product
        """
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            instance = self.get_object()
            instance.delete()
            return Response({"message":"Product deleted successfully"}, status=status.HTTP_200_OK)
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


##########################
#  ORDER
##########################
class OrderViewSet(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, mixins.CreateModelMixin, mixins.DestroyModelMixin, viewsets.GenericViewSet):
    queryset = Order.objects.all()
    serializers = {
        'default': OrderSerializer,
        'create': CreateOrderSerializer,
        'update': UpdateOrderSerializer,
        'partial_update': UpdateOrderSerializer,
    }
    permission_classes = [
        IsAuthenticated
    ]
    
    def get_queryset(self):                                      
        return super().get_queryset()

    def get_serializer_class(self):
        return self.serializers.get(self.action, self.serializers['default'])

    def list(self, request):
        """
        Create order
        """
        queryset = self.get_queryset()
        queryset = self.queryset.filter(user_id = request.user.id)
        try:
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                paginated_response = self.get_paginated_response(serializer.data)
                paginated_response.data['message'] = "Orders retrived successfully"
                return paginated_response
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    def create(self, request):
        """
        Create order
        """        
        try:
            user = User.objects.filter(id = request.data['user'])[0]
            if user is None:
                return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            if not user.is_active:
                return Response({'message': 'User has been deactivated'}, status=status.HTTP_403_FORBIDDEN)
            
            for product_id in request.data['products']:
                if not Product.objects.filter(id = product_id).exists():
                    return Response({'message': f'Product {product_id} not found'}, status=status.HTTP_404_NOT_FOUND)
                    
            
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            serializer = OrderSerializer(Order.objects.get(id = serializer.data['id']))
            return Response({"message": "Order created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        
        except:
            return Response({'message': 'Something went wrong'}, status=status.HTTP_400_BAD_REQUEST)
        
        
    def retrieve(self, request, *args, **kwargs):
        """
        Get order
        """
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            serializer = self.get_serializer(instance)
            return Response({"message":"Order retrived successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def update(self, request, *args, **kwargs):
        """
        Update order
        """
        partial = kwargs.pop('partial', False)
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
            
        try:
            if request.data['products']:
                for product_id in request.data['products']:
                    if not Product.objects.filter(id = product_id).exists():
                        return Response({'message': f'Product {product_id} not found'}, status=status.HTTP_404_NOT_FOUND)
            
            user =  User.objects.filter(id = request.data['user'])[0]
            if user:
                if user is None:
                    return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
                if not user.is_active:
                    return Response({'message': 'User has been deactivated'}, status=status.HTTP_403_FORBIDDEN)
                
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            serializer = OrderSerializer(Order.objects.get(id = serializer.data['id']))
            return Response({"message": "Order updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    def destroy(self, request, *args, **Kwargs):
        """
        Delete order
        """
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            instance = self.get_object()
            instance.delete()
            return Response({"message":"Order deleted successfully"}, status=status.HTTP_200_OK)
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)