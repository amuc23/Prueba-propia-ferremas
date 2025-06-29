from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from .serializers import UsuarioSerializer, LoginSerializer, UsuarioListaSerializer
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from .models import Usuario
from django.contrib.auth.decorators import user_passes_test
from carro_compras.models import Venta
from django.utils import timezone
from django.contrib.auth.views import PasswordResetView
from django.urls import reverse_lazy, reverse
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.core.mail import send_mail
from django.conf import settings

signer = TimestampSigner()

# ===================== VISTAS HTML =======================

def iniciosesion(request):
    return render(request, 'usuarios/iniciosesion.html')

def registro(request):
    return render(request, 'usuarios/registro.html')

def cerrar_sesion(request):
    logout(request)
    return redirect('/')

def vista_registro_pendiente(request):
    return render(request, 'usuarios/registro_pendiente.html')

def activar_cuenta(request, token):
    try:
        email = signer.unsign(token, max_age=60 * 60 * 24)  # 24 horas
        user = Usuario.objects.get(email=email)
        user.is_active = True
        user.email_confirmado = True
        user.save()
        return render(request, 'usuarios/activacion_exitosa.html')
    except (BadSignature, SignatureExpired, Usuario.DoesNotExist):
        return render(request, 'usuarios/activacion_fallida.html')

@user_passes_test(lambda u: u.is_staff)
def vista_lista_usuarios(request):
    return render(request, 'usuarios/lista_usuarios.html')

@user_passes_test(lambda u: u.is_staff, login_url='/usuarios/iniciosesion/')
def vista_agregar_usuario(request):
    return render(request, 'usuarios/agregar_usuario.html')

@user_passes_test(lambda u: u.is_staff)
def vista_editar_usuario(request, id):
    usuario = get_object_or_404(Usuario, id=id)
    return render(request, 'usuarios/editar_usuario.html', {'usuario': usuario})


# ===================== API REST ==========================

class RegistroAPIView(APIView):
    def post(self, request):
        serializer = UsuarioSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.is_active = False
            user.save()

            token = signer.sign(user.email)
            activation_url = request.build_absolute_uri(
                reverse('activar_cuenta', args=[token])
            )

            send_mail(
                subject='Activa tu cuenta en FERREMAS',
                message=f'Hola {user.first_name}, activa tu cuenta usando este enlace:\n{activation_url}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
            )

            return Response({
                'status': 'success',
                'message': 'Usuario registrado. Revisa tu correo para activarlo.',
                'redirect_url': '/usuarios/registro/pendiente/'
            }, status=201)

        return Response(serializer.errors, status=400)

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
    if usuario == request.user:
        return Response({"error": "No puedes suspender tu propia cuenta."}, status=403)
    usuario.is_active = not usuario.is_active
    usuario.save()
    return Response({"message": "Estado actualizado", "is_active": usuario.is_active})

@api_view(['PUT'])
@permission_classes([IsAdminUser])
def api_editar_usuario(request, id):
    usuario = get_object_or_404(Usuario, id=id)
    if not usuario.is_active:
        return Response({"error": "No puedes editar un usuario suspendido."}, status=403)
    if request.user == usuario:
        return Response({"error": "No puedes editar tu propia cuenta desde el panel."}, status=403)
    serializer = UsuarioSerializer(usuario, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=200)
    return Response(serializer.errors, status=400)


# ===================== RECUPERAR CONTRASEÑA ==========================

class VistaRecuperarConValidacion(PasswordResetView):
    template_name = 'usuarios/recuperar.html'
    email_template_name = 'usuarios/password_reset_email.html'
    subject_template_name = 'usuarios/password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        email = form.cleaned_data['email']
        Usuario = get_user_model()
        if not Usuario.objects.filter(email=email).exists():
            messages.error(self.request, "El correo ingresado no está registrado.")
            return self.form_invalid(form)
        return super().form_valid(form)
