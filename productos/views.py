from django.shortcuts import render
from .models import Producto
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import ProductoSerializer

#--------------------GET-----------------------

# Vista HTML (muestra los productos en formato HTML)
def lista_productos(request):
    productos = Producto.objects.all()  # Obtiene todos los productos
    return render(request, 'productos/lista_productos.html', {'productos': productos})  # Renderiza la plantilla HTML

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

# Vista para el CRUD de productos (muestra todos los productos)
def crud_productos(request):
    productos = Producto.objects.all()  # Obtiene todos los productos
    return render(request, 'productos/crud_productos.html', {'productos': productos})  # Renderiza la plantilla HTML
#------------------#

def detalle_producto(request, id):
    try:
        producto = Producto.objects.get(id=id)
    except Producto.DoesNotExist:
        return render(request, 'productos/404.html')  # Página de error si no se encuentra el producto
    return render(request, 'productos/detalle.html', {'producto': producto})
#--------------------------------
@api_view(['DELETE'])
def api_eliminar_producto(request, id):
    try:
        producto = Producto.objects.get(id=id)
        producto.delete()
        return Response({'mensaje': 'Producto eliminado'}, status=status.HTTP_204_NO_CONTENT)
    except Producto.DoesNotExist:
        return Response({'error': 'Producto no encontrado'}, status=status.HTTP_404_NOT_FOUND)