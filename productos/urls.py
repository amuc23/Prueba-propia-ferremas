from django.urls import path
from . import views

urlpatterns = [
    path('productos/<int:id>/', views.detalle_producto, name='detalle_producto'),  # Ruta para ver el detalle del producto
    path('productos/', views.lista_productos, name='lista_productos'),  # Ruta para la lista de productos
    path('productos/api/', views.api_lista_productos, name='api_lista_productos'),  # Ruta API para los productos
    path('productos/api/agregar/', views.api_agregar_producto, name='api_agregar_producto'),  # Ruta API para agregar productos
    path('productos/formulario/', views.formulario_producto, name='formulario_producto'),  # Ruta para formulario de agregar productos
    path('productos/crud/', views.crud_productos, name='crud_productos'),  # Ruta para el CRUD de productos
    path('productos/api/eliminar/<int:id>/', views.api_eliminar_producto, name='api_eliminar_producto'),
]
