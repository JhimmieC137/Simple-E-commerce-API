import jwt
from datetime import datetime, timedelta

# Django Iports
from django.contrib.auth import login, logout, authenticate
from django.core.exceptions import ValidationError
from django.db.models import Q


# DRF Imports
from rest_framework import viewsets, mixins
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken

# Core Iports
from app.settings import SECRET_KEY
from core.models import User
from core.serializers import *



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
            user = self.queryset.filter(email = request.data['email']).exists()
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
            user = self.queryset.get(email = request.data['email'])
            if user:
                if  user.is_active:
                    user = authenticate(email=request.data['email'], password=request.data['password'])
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
            user = self.queryset.get(email = request.data['email'])
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



class UserViewSet(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """
    Creates, Updates and Retrieves - User Accounts
    """
    parser_classes = (MultiPartParser, FormParser)
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
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return Response({"message": "Users retrived successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        except:
            return Response({"message": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response({"message":"User retrived successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        except:
            return Response({"message": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        
        
    def perform_update(self, serializer):
        serializer.save()
        
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        
        try:
            instance = self.get_object()
        except:
            return Response({"message": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
        except:
            return Response({"message": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)
        
        
        self.perform_update(serializer)
        return Response({"message": "User updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)