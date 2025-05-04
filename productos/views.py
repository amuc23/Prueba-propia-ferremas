from django.shortcuts import render, redirect, get_object_or_404
from .models import Producto
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import ProductoSerializer
import requests
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt  

#--------------------GET-----------------------

# Vista HTML (muestra los productos en formato HTML)
#def lista_productos(request):
#    productos = Producto.objects.all()  # Obtiene todos los productos
#    return render(request, 'productos/lista_productos.html', {'productos': productos})  # Renderiza la plantilla HTML


def lista_productos(request):
    return render(request, 'productos/lista_productos.html')


# Vista API (muestra los productos en formato JSON)
@api_view(['GET'])
def api_lista_productos(request):
    productos = Producto.objects.all()  # Obtiene todos los productos
    serializer = ProductoSerializer(productos, many=True)  # Serializa los productos
    return Response(serializer.data)  # Devuelve los productos en formato JSON

#--------------------POST----------------------

# Vista API para agregar un nuevo producto (POST)
@api_view(['POST'])
def api_agregar_producto(request):
    if request.method == 'POST':
        serializer = ProductoSerializer(data=request.data)  # Serializa los datos recibidos
        if serializer.is_valid():  # Verifica si los datos son válidos
            serializer.save()  # Guarda el nuevo producto
            return Response(serializer.data, status=status.HTTP_201_CREATED)  # Devuelve el producto creado
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  # Error de validación

# Vista para mostrar el formulario de agregar producto
def formulario_producto(request):
    return render(request, 'productos/formulario_producto.html')



def lista_productos_crud(request):
    return render(request, 'productos/crud_productos.html')



def detalle_producto(request, id):
    try:
        producto = Producto.objects.get(id=id)
    except Producto.DoesNotExist:
        return render(request, 'productos/404.html')  # Página de error si no se encuentra el producto
    return render(request, 'productos/detalle.html', {'producto': producto})
#--------------------------------

def eliminar_producto(request, id):
    if request.method == 'POST':
        producto = get_object_or_404(Producto, id=id)
        producto.delete()
    return redirect('crud_productos')