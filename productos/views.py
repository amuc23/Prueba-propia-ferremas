from django.shortcuts import render, get_object_or_404
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from .models import Producto
from .serializers import ProductoSerializer
from rest_framework.permissions import BasePermission
from django.contrib.auth.decorators import user_passes_test
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponse

#--------------------GET-----------------------

# Vista HTML (muestra los productos en formato HTML)
#def lista_productos(request):
#    productos = Producto.objects.all()  # Obtiene todos los productos
#    return render(request, 'productos/lista_productos.html', {'productos': productos})  # Renderiza la plantilla HTML





def lista_productos(request):
    return render(request, 'productos/lista_productos.html', {
        'entorno': settings.ENTORNO
    })

# Vista API (muestra los productos en formato JSON)
@api_view(['GET'])
def api_lista_productos(request):
    productos = Producto.objects.all()  # Obtiene todos los productos
    serializer = ProductoSerializer(productos, many=True)  # Serializa los productos
    return Response(serializer.data)  # Devuelve los productos en formato JSON

#--------------------POST----------------------
class EsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_staff

def es_admin(user):
    return user.is_authenticated and user.is_staff

@user_passes_test(es_admin)
def formulario_producto(request):
    return render(request, 'productos/formulario_producto.html')

@api_view(['POST'])
@permission_classes([EsAdmin])
def api_agregar_producto(request):
    serializer = ProductoSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





def detalle_producto(request, id):
    try:
        producto = Producto.objects.get(id=id)
    except Producto.DoesNotExist:
        return render(request, 'productos/404.html')  # Página de error si no se encuentra el producto
    return render(request, 'productos/detalle.html', {'producto': producto})
#--------------------------------


@csrf_exempt
@require_http_methods(["DELETE"])
@login_required(login_url='/usuarios/iniciosesion/')
def api_eliminar_producto(request, id):
    if not request.user.is_staff:
        return JsonResponse({'error': 'No tienes permisos para eliminar productos.'}, status=403)

    try:
        from .models import Producto
        producto = Producto.objects.get(id=id)
        producto.delete()
        return JsonResponse({'mensaje': 'Producto eliminado correctamente'}, status=204)
    except Producto.DoesNotExist:
        return JsonResponse({'error': 'Producto no encontrado'}, status=404)


    
    # Usar el decorador para proteger la vista
@user_passes_test(es_admin, login_url='/')  # Redirige a la página principal si no es admin
def lista_productos_crud(request):
    return render(request, 'productos/crud_productos.html', {
        'entorno': settings.ENTORNO
    })

@api_view(['PUT'])
@permission_classes([EsAdmin])
def api_editar_producto(request, id):
    producto = get_object_or_404(Producto, id=id)
    serializer = ProductoSerializer(producto, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# Vista protegida: solo accesible por administradores
@user_passes_test(es_admin, login_url='/usuarios/iniciosesion/')
def editar_producto(request, id):
    producto = get_object_or_404(Producto, id=id)
    return render(request, 'productos/editar_producto.html', {
        'producto': producto,
        'entorno': settings.ENTORNO
    })
@login_required
def prueba_permisos(request):
    return HttpResponse(f"Usuario: {request.user.username} | Staff: {request.user.is_staff}")