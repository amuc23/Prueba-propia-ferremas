from django.urls import path
from . import views

urlpatterns = [
    path('', views.lista_productos, name='lista_productos'),  # Vista HTML
    path('api/', views.api_lista_productos, name='api_lista_productos'),  # Vista API JSON
    path('api/agregar/', views.api_agregar_producto, name='api_agregar_producto'),  # Crear producto (POST)
    path('formulario/', views.formulario_producto, name='formulario_producto'),  # Vista para el formulario HTML
    path('crud/', views.crud_productos, name='crud_productos'),


]
