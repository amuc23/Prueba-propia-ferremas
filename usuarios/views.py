from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from .serializers import UsuarioSerializer, LoginSerializer
from django.http import JsonResponse

def iniciosesion(request):
    return render(request, 'usuarios/iniciosesion.html')

def registro(request):
    return render(request, 'usuarios/registro.html')

def cerrar_sesion(request):
    logout(request)
    return redirect('/')

class RegistroAPIView(APIView):
    def post(self, request):
        serializer = UsuarioSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'status': 'success',
                'message': 'Usuario registrado exitosamente',
                'token': token.key,
                'redirect_url': '/'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'status': 'success',
                'message': 'Inicio de sesión exitoso',
                'token': token.key,
                'redirect_url': '/'
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)