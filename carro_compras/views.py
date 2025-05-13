from django.conf import settings
from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Venta, Detalle
from .serializers import VentaSerializer
from productos.models import Producto
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.shortcuts import redirect
from django.http import HttpResponse
from transbank.common.options import WebpayOptions
from transbank.common.integration_type import IntegrationType
from transbank.webpay.webpay_plus.transaction import Transaction
import time  # ⬅️ pon esto al inicio del archivo si no lo tienes

# Vista para renderizar la plantilla HTML del carrito

def vista_carrito(request):
    if request.user.is_authenticated:
        # Obtener el carrito activo para el usuario
        venta = Venta.objects.filter(id_usuario=request.user, estado_venta='carrito').first()

        if venta:
            # Obtener todos los detalles del carrito
            detalles = Detalle.objects.filter(id_venta=venta)
            productos_eliminados = []

            # Eliminar productos con stock cero y guardar los eliminados para mostrarlos
            for detalle in detalles:
                if detalle.producto.stock <= 0:
                    productos_eliminados.append(detalle)
                    detalle.delete()

            # Recalcular detalles después de eliminar
            detalles = Detalle.objects.filter(id_venta=venta)

            # Calcular el total del carrito actualizado
            total_carrito = sum(d.subtotal_venta for d in detalles)

            return render(request, 'carro_compras/carrito.html', {
                'entorno': settings.ENTORNO,
                'detalles': detalles,
                'total_carrito': total_carrito,
                'productos_eliminados': productos_eliminados
            })
        else:
            return render(request, 'carro_compras/carrito.html', {
                'entorno': settings.ENTORNO,
                'mensaje': 'No tienes productos en tu carrito.'
            })
    else:
        return render(request, 'carro_compras/carrito.html', {
            'entorno': settings.ENTORNO,
            'mensaje': 'Por favor, inicia sesión para ver tu carrito.'
        })


# Vista para gestionar el carrito (ver y crear)
@api_view(['GET', 'POST'])
def gestionar_carrito(request):
    if request.user.is_authenticated:
        if request.method == 'GET':
            # Buscar carrito abierto para el usuario
            venta = Venta.objects.filter(id_usuario=request.user, estado_venta='carrito').first()
            if venta:
                # Si existe un carrito, devolvemos sus detalles
                serializer = VentaSerializer(venta)
                return Response(serializer.data)
            return Response({"detail": "No hay carrito abierto."}, status=status.HTTP_404_NOT_FOUND)

        elif request.method == 'POST':
            # Crear un nuevo carrito (venta)
            venta = Venta.objects.create(
                id_usuario=request.user,
                fecha_compra=timezone.now(),
                total_venta=0,
                estado_venta='carrito'
            )

            # Crear detalles de la venta
            detalles_data = request.data.get('detalles', [])
            for detalle_data in detalles_data:
                try:
                    producto = Producto.objects.get(id=detalle_data['producto'])
                    Detalle.objects.create(
                        id_venta=venta,
                        producto=producto,
                        cantidad_producto=detalle_data['cantidad_producto'],
                        subtotal_venta=producto.precio * detalle_data['cantidad_producto']
                    )
                except Producto.DoesNotExist:
                    return Response({"detail": "Producto no encontrado."}, status=status.HTTP_400_BAD_REQUEST)

            # Devolver el carrito creado
            return Response({"message": "Carrito creado exitosamente."}, status=status.HTTP_201_CREATED)
    return Response({"detail": "Usuario no autenticado."}, status=status.HTTP_401_UNAUTHORIZED)

# Vista para agregar productos al carrito
@api_view(['POST'])
def agregar_producto_carrito(request):
    if request.user.is_authenticated:
        # Obtener el carrito abierto (si existe)
        venta = Venta.objects.filter(id_usuario=request.user, estado_venta='carrito').first()

        if not venta:
            # Si no existe un carrito, creamos uno nuevo
            venta = Venta.objects.create(
                id_usuario=request.user,
                fecha_compra=timezone.now(),
                total_venta=0,
                estado_venta='carrito'
            )

        # Obtener datos del producto
        producto_id = request.data.get('producto')
        cantidad = request.data.get('cantidad_producto')

        try:
            producto = Producto.objects.get(id=producto_id)
        except Producto.DoesNotExist:
            return Response({"detail": "Producto no encontrado."}, status=status.HTTP_400_BAD_REQUEST)

        # Verificar si el producto ya está en el carrito
        detalle_existente = Detalle.objects.filter(id_venta=venta, producto=producto).first()

        if detalle_existente:
            return Response({"detail": "Este producto ya está en tu carrito."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Si no existe, agregamos un nuevo detalle al carrito
        Detalle.objects.create(
            id_venta=venta,
            producto=producto,
            cantidad_producto=cantidad,
            subtotal_venta=producto.precio * cantidad
        )

        # Recalcular el total de la venta
        venta.total_venta = sum(d.subtotal_venta for d in venta.detalles.all())
        venta.save()

        return Response({"message": "Producto agregado al carrito exitosamente."})
    return Response({"detail": "Usuario no autenticado."}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['PUT'])
def actualizar_cantidad_producto(request, detalle_id):
    if request.user.is_authenticated:
        try:
            detalle = Detalle.objects.get(id=detalle_id)
        except Detalle.DoesNotExist:
            return Response({"detail": "Detalle no encontrado."}, status=status.HTTP_404_NOT_FOUND)

        cantidad_nueva = request.data.get('cantidad_producto')

        # Verificar que la cantidad no sea menor a 1
        if cantidad_nueva <= 0:
            # Eliminar el detalle si la cantidad es 0 o menos
            detalle.delete()
            venta = detalle.id_venta
            venta.total_venta = sum(d.subtotal_venta for d in venta.detalles.all())
            venta.save()

            return Response({"message": "Producto eliminado del carrito.", "total_carrito": venta.total_venta})

        # Verificar stock
        if cantidad_nueva > detalle.producto.stock:
            return Response({"detail": f"Solo hay {detalle.producto.stock} unidades disponibles."}, status=status.HTTP_400_BAD_REQUEST)

        # Actualizar la cantidad del producto y el subtotal
        detalle.cantidad_producto = cantidad_nueva
        detalle.subtotal_venta = detalle.producto.precio * cantidad_nueva
        detalle.save()

        # Actualizar el total de la venta
        venta = detalle.id_venta
        venta.total_venta = sum(d.subtotal_venta for d in venta.detalles.all())
        venta.save()

        # Devolver el nuevo subtotal y total
        return Response({
            "subtotal_venta": detalle.subtotal_venta,
            "total_carrito": venta.total_venta
        })

    return Response({"detail": "Usuario no autenticado."}, status=status.HTTP_401_UNAUTHORIZED)



# Vista para disminuir la cantidad de un producto
@api_view(['PUT'])
def disminuir_cantidad_producto(request, detalle_id):
    if request.user.is_authenticated:
        try:
            detalle = Detalle.objects.get(id=detalle_id)
        except Detalle.DoesNotExist:
            return Response({"detail": "Detalle no encontrado."}, status=status.HTTP_404_NOT_FOUND)

        # Si la cantidad es 1, eliminamos el producto del carrito
        if detalle.cantidad_producto == 1:
            detalle.delete()
            venta = detalle.id_venta
            venta.total_venta = sum(d.subtotal_venta for d in venta.detalles.all())
            venta.save()

            return Response({"message": "Producto eliminado del carrito.", "total_carrito": venta.total_venta})

        # Decrementar la cantidad y actualizar el subtotal
        detalle.cantidad_producto -= 1
        detalle.subtotal_venta = detalle.producto.precio * detalle.cantidad_producto
        detalle.save()

        # Actualizar el total de la venta
        venta = detalle.id_venta
        venta.total_venta = sum(d.subtotal_venta for d in venta.detalles.all())
        venta.save()

        return Response({
            "subtotal_venta": detalle.subtotal_venta,
            "total_carrito": venta.total_venta
        })

    return Response({"detail": "Usuario no autenticado."}, status=status.HTTP_401_UNAUTHORIZED)
#####################


@api_view(['POST'])
def iniciar_pago_webpay(request):
    if not request.user.is_authenticated:
        return Response({'error': 'Debes iniciar sesión'}, status=401)

    venta = Venta.objects.filter(id_usuario=request.user, estado_venta='carrito').first()
    if not venta:
        return Response({'error': 'No tienes un carrito activo'}, status=404)

    options = WebpayOptions(
        commerce_code='597055555532',
        api_key='579B532A7440BB0C9079DED94D31EA1615BACEB56610332264630D42D0A36B1C',
        integration_type=IntegrationType.TEST
    )

    try:
        tx = Transaction(options)
        import time
        buy_order = f"{venta.id}-{int(time.time())}"

        # Usar build_absolute_uri para que funcione tanto local como en Railway
        return_url = request.build_absolute_uri('/api/webpay/respuesta/')

        response = tx.create(
            buy_order=buy_order,
            session_id=str(request.user.id),
            amount=venta.total_venta,
            return_url=return_url
        )

        venta.webpay_transaction_id = response['token']
        venta.save()

        return redirect(response['url'] + "?token_ws=" + response['token'])

    except Exception as e:
        print("❌ ERROR AL CREAR TRANSACCIÓN:")
        print(e)
        return Response({'error': 'Error al crear la transacción con WebPay', 'detalle': str(e)}, status=500)

    
@csrf_exempt
@require_http_methods(["GET", "POST"])
def respuesta_pago_webpay(request):
    token = request.POST.get("token_ws") or request.GET.get("token_ws")

    if not token:
        return redirect('/carrito/?mensaje=Transacción cancelada.')

    options = WebpayOptions(
        commerce_code='597055555532',
        api_key='579B532A7440BB0C9079DED94D31EA1615BACEB56610332264630D42D0A36B1C',
        integration_type=IntegrationType.TEST
    )

    tx = Transaction(options)

    try:
        response = tx.commit(token)
        id_venta = str(response['buy_order']).split("-")[0]
        venta = Venta.objects.get(id=int(id_venta))

        if response['status'] == 'AUTHORIZED':
            venta.estado_venta = 'pagado'
            venta.fecha_compra = timezone.now()
            venta.webpay_payment_status = 'completed'
            venta.save()

            # ✅ Descontar stock por cada producto vendido
            for detalle in venta.detalles.all():
                producto = detalle.producto
                producto.stock -= detalle.cantidad_producto
                producto.save()

            mensaje = "✅ Pago realizado con éxito"
        else:
            venta.webpay_payment_status = 'failed'
            venta.save()
            mensaje = "❌ Pago rechazado"

    except Exception as e:
        return HttpResponse(f"<b>Error al procesar la transacción:</b> {e}")

    return render(request, 'carro_compras/webpay_respuesta.html', {
        'mensaje': mensaje,
        'venta': venta,
        'response': response
    })


def vista_historial_ventas(request):
    ventas = Venta.objects.filter(estado_venta='pagado').order_by('-fecha_compra')
    return render(request, 'carro_compras/historial_ventas.html', {'ventas': ventas})