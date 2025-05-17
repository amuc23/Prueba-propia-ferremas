from django.urls import path
from . import views
from .views import RegistroAPIView, LoginAPIView
from django.contrib.auth import views as auth_views
from .views import VistaRecuperarConValidacion

urlpatterns = [
    path('usuarios/iniciosesion/', views.iniciosesion, name='iniciosesion'),
    path('usuarios/registro/', views.registro, name='registro'),
    path('usuarios/cerrar-sesion/', views.cerrar_sesion, name='cerrar_sesion'),

    # API REST
    path('api/registro/', RegistroAPIView.as_view(), name='api_registro'),
    path('api/login/', LoginAPIView.as_view(), name='api_login'),
    path('api/usuarios/', views.api_lista_usuarios, name='api_lista_usuarios'),
    path('api/usuarios/agregar/', views.api_agregar_usuario, name='api_agregar_usuario'),
    path('api/usuarios/toggle-activo/<int:id>/', views.api_toggle_activo_usuario, name='api_toggle_activo_usuario'),
    path('api/usuarios/editar/<int:id>/', views.api_editar_usuario, name='api_editar_usuario'),

    # Vistas HTML
    path('usuarios/lista/', views.vista_lista_usuarios, name='vista_lista_usuarios'),
    path('usuarios/agregar/', views.vista_agregar_usuario, name='vista_agregar_usuario'),
    path('usuarios/editar/<int:id>/', views.vista_editar_usuario, name='vista_editar_usuario'),

    # Recuperar contraseña (con plantillas personalizadas)
    path('usuarios/recuperar/', VistaRecuperarConValidacion.as_view(), name='password_reset'),


    path('usuarios/recuperar/enviado/', auth_views.PasswordResetDoneView.as_view(
        template_name='usuarios/recuperar_enviado.html'
    ), name='password_reset_done'),

    path('usuarios/restablecer/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='usuarios/restablecer.html'
    ), name='password_reset_confirm'),

    path('usuarios/restablecer/completo/', auth_views.PasswordResetCompleteView.as_view(
        template_name='usuarios/restablecer_completo.html'
    ), name='password_reset_complete'),

    path('usuarios/restablecer/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
    template_name='usuarios/restablecer.html',
    post_reset_login=False,
    extra_context={"title": "Restablecer contraseña"},
    success_url='/usuarios/restablecer/completo/',
), name='password_reset_confirm'),

]
