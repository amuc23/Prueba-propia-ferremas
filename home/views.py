from django.shortcuts import render
from productos.models import Producto  # importar modelo Producto
from django.contrib.auth.decorators import user_passes_test

def index(request):
    productos_destacados = Producto.objects.all().order_by('-id')[:3]  # los 3 más recientes
    return render(request, 'home/index.html', {'productos_destacados': productos_destacados})

@user_passes_test(lambda u: u.is_staff, login_url='/usuarios/iniciosesion/')
def panel_administracion(request):
    return render(request, 'home/panel_admin.html')

def contacto(request):
    return render(request, 'home/contacto.html')

def custom_404(request, exception):
    return render(request, '404.html', status=404)