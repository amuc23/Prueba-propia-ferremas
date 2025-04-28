from django.shortcuts import render
from productos.models import Producto  # importar modelo Producto

def index(request):
    productos_destacados = Producto.objects.all().order_by('-id')[:3]  # los 3 más recientes
    return render(request, 'home/index.html', {'productos_destacados': productos_destacados})
