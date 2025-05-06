from django.urls import path
from . import views

urlpatterns = [
    path('productos/<int:id>/', views.detalle_producto, name='detalle_producto'),
    path('productos/', views.lista_productos, name='lista_productos'),
    path('productos/crud/', views.lista_productos_crud, name='lista_productos_crud'),
    path('productos/api/', views.api_lista_productos, name='api_lista_productos'),
    path('productos/api/agregar/', views.api_agregar_producto, name='api_agregar_producto'),
    path('productos/formulario/', views.formulario_producto, name='formulario_producto'),
    path('productos/api/eliminar/<int:id>/', views.api_eliminar_producto, name='api_eliminar_producto'),
    path('productos/api/editar/<int:id>/', views.api_editar_producto, name='api_editar_producto'),
    path('productos/editar/<int:id>/', views.editar_producto, name='editar_producto'),
    path('productos/prueba/', views.prueba_permisos),

]
