from django.urls import path
from . import views
from .views import RegistroAPIView, LoginAPIView

urlpatterns = [
    path('usuarios/iniciosesion/', views.iniciosesion, name='iniciosesion'),
    path('usuarios/registro/', views.registro, name='registro'),
    path('usuarios/cerrar-sesion/', views.cerrar_sesion, name='cerrar_sesion'),
    path('api/registro/', RegistroAPIView.as_view(), name='api_registro'),
    path('api/login/', LoginAPIView.as_view(), name='api_login'),
    path('api/usuarios/', views.api_lista_usuarios, name='api_lista_usuarios'),
    path('usuarios/lista/', views.vista_lista_usuarios, name='vista_lista_usuarios'),
    path('api/usuarios/agregar/', views.api_agregar_usuario, name='api_agregar_usuario'),
    path('usuarios/agregar/', views.vista_agregar_usuario, name='vista_agregar_usuario'),
    path('api/usuarios/toggle-activo/<int:id>/', views.api_toggle_activo_usuario, name='api_toggle_activo_usuario'),
    path('usuarios/editar/<int:id>/', views.vista_editar_usuario, name='vista_editar_usuario'),
    path('api/usuarios/editar/<int:id>/', views.api_editar_usuario, name='api_editar_usuario'),





]