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

]