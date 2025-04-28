from django.shortcuts import render
from .models import Producto

# Vista HTML (ya la tienes bien)
def lista_productos(request):
    productos = Producto.objects.all()
    return render(request, 'productos/lista_productos.html', {'productos': productos})

# Vista API
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import ProductoSerializer

@api_view(['GET'])
def api_lista_productos(request):
    productos = Producto.objects.all()
    serializer = ProductoSerializer(productos, many=True)
    return Response(serializer.data)
