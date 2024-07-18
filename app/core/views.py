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

# Core Iports
from core.models import User
from core.serializers import *



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
    
    
    @action(detail=False, methods=['get'], url_path='me', url_name='me')
    def session(self, instance):
        """
        User in session
        """
        try:
            return Response(UserSerializer(self.request.user, context={'request': self.request}).data, status=status.HTTP_200_OK)
        except:
            return Response({'message': 'Wrong auth token'}, status=status.HTTP_400_BAD_REQUEST)
    
    
    def list(self, request):
        queryset = self.get_queryset()
        queryset = self.queryset.filter(
            Q(name__icontains = request.query_params.get('search') if request.query_params.get('search') else '') |
            Q(email__icontains = request.query_params.get('search') if request.query_params.get('search') else '')
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
        
        
    def retrieve(self, request):
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