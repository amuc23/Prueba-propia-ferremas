from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from .serializers import UsuarioSerializer, LoginSerializer
from .serializers import UsuarioListaSerializer
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from .models import Usuario
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import get_object_or_404
from carro_compras.models import Venta
from django.utils import timezone


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
    


@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_lista_usuarios(request):
    usuarios = Usuario.objects.all()
    serializer = UsuarioListaSerializer(usuarios, many=True)
    return Response(serializer.data)    

@user_passes_test(lambda u: u.is_staff)
def vista_lista_usuarios(request):
    return render(request, 'usuarios/lista_usuarios.html')

################################################################
@user_passes_test(lambda u: u.is_staff, login_url='/usuarios/iniciosesion/')
def vista_agregar_usuario(request):
    return render(request, 'usuarios/agregar_usuario.html')


@api_view(['POST'])
@permission_classes([IsAdminUser])
def api_agregar_usuario(request):
    serializer = UsuarioSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)    

@api_view(['PATCH'])
@permission_classes([IsAdminUser])
def api_toggle_activo_usuario(request, id):
    usuario = get_object_or_404(Usuario, id=id)

    # Evitar que un administrador se auto-banee
    if usuario == request.user:
        return Response(
            {"error": "No puedes suspender tu propia cuenta."},
            status=403
        )

    usuario.is_active = not usuario.is_active
    usuario.save()
    return Response({"message": "Estado actualizado", "is_active": usuario.is_active})

@user_passes_test(lambda u: u.is_staff)
def vista_editar_usuario(request, id):
    usuario = get_object_or_404(Usuario, id=id)
    return render(request, 'usuarios/editar_usuario.html', {'usuario': usuario})


@api_view(['PUT'])
@permission_classes([IsAdminUser])
def api_editar_usuario(request, id):
    usuario = get_object_or_404(Usuario, id=id)

    # 🚫 No permitir editar usuarios suspendidos
    if not usuario.is_active:
        return Response({"error": "No puedes editar un usuario suspendido."}, status=status.HTTP_403_FORBIDDEN)

    # 🚫 No permitir editarse a uno mismo
    if request.user == usuario:
        return Response({"error": "No puedes editar tu propia cuenta desde el panel."}, status=status.HTTP_403_FORBIDDEN)

    serializer = UsuarioSerializer(usuario, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


