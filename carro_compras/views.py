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
from django.template.loader import get_template
from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from .models import Venta, Detalle
from rest_framework.permissions import IsAdminUser
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated





def vista_carrito(request):
    if request.user.is_authenticated:
        venta = Venta.objects.filter(id_usuario=request.user, estado_venta='carrito').first()

        if venta:
            detalles = Detalle.objects.filter(id_venta=venta)
            productos_eliminados = []

            for detalle in detalles:
                producto = detalle.producto
                if producto.stock <= 0 or not producto.activo:
                    productos_eliminados.append(detalle)
                    detalle.delete()
                elif detalle.cantidad_producto > producto.stock:
                    detalle.cantidad_producto = producto.stock
                    detalle.subtotal_venta = producto.precio * producto.stock
                    detalle.save()

            detalles = Detalle.objects.filter(id_venta=venta)
            total_carrito = sum(d.subtotal_venta for d in detalles)
            venta.total_venta = total_carrito
            venta.save()

            return render(request, 'carro_compras/carrito.html', {
                'entorno': settings.ENTORNO,
                'detalles': detalles,
                'total_carrito': total_carrito,
                'productos_eliminados': productos_eliminados
            })
        else:
            # 👇 Mostrar vista sin productos, sin mensaje personalizado
            return render(request, 'carro_compras/carrito.html', {
                'entorno': settings.ENTORNO,
                'detalles': [],
                'total_carrito': 0,
                'productos_eliminados': []
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

    # NO guardar tipo_entrega ni dirección aquí porque el pago aún no está confirmado
    # Los datos los puedes guardar luego en respuesta_pago_webpay solo si el pago es exitoso
    # Pero si necesitas recibirlos aquí, guárdalos temporalmente en variables
    tipo_entrega = request.POST.get('tipo_entrega')
    direccion_despacho = request.POST.get('direccion_despacho') if tipo_entrega == 'despacho' else ''

    options = WebpayOptions(
        commerce_code='597055555532',
        api_key='579B532A7440BB0C9079DED94D31EA1615BACEB56610332264630D42D0A36B1C',
        integration_type=IntegrationType.TEST
    )

    tx = Transaction(options)
    import time
    buy_order = f"{venta.id}-{int(time.time())}"
    return_url = request.build_absolute_uri('/api/webpay/respuesta/')

    response = tx.create(
        buy_order=buy_order,
        session_id=str(request.user.id),
        amount=venta.total_venta,
        return_url=return_url
    )

    venta.webpay_transaction_id = response['token']
    venta.save()

    # Guardar temporalmente tipo_entrega y dirección en sesión para luego confirmar
    request.session['tipo_entrega'] = tipo_entrega
    request.session['direccion_despacho'] = direccion_despacho

    return redirect(response['url'] + "?token_ws=" + response['token'])
    
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

        if not venta.detalles.exists():
            return HttpResponse("No puedes completar el pago: el carrito está vacío.")

        if response['status'] == 'AUTHORIZED':
            # Obtener datos de entrega guardados en sesión
            tipo_entrega = request.session.get('tipo_entrega', '')
            direccion_despacho = request.session.get('direccion_despacho', '')

            venta.tipo_entrega = tipo_entrega
            venta.direccion_despacho = direccion_despacho
            venta.estado_entrega = 'pendiente'
            venta.estado_venta = 'pagado'
            venta.fecha_compra = timezone.now()
            venta.webpay_payment_status = 'completed'
            
            # ✅ Aquí se guarda el número de tarjeta (últimos 4 dígitos)
            venta.ultimos_digitos = response.get('card_detail', {}).get('card_number', '')[-4:]

            venta.total_venta = sum(d.subtotal_venta for d in venta.detalles.all())
            venta.save()


            for detalle in venta.detalles.all():
                producto = detalle.producto
                producto.stock -= detalle.cantidad_producto
                producto.save()

            # Limpiar sesión
            request.session.pop('tipo_entrega', None)
            request.session.pop('direccion_despacho', None)

            mensaje = "✅ Pago realizado con éxito"

        else:
            # ❌ Pago rechazado: mantener como carrito y limpiar todo
            venta.estado_venta = 'carrito'
            venta.tipo_entrega = ''
            venta.direccion_despacho = ''
            venta.estado_entrega = ''
            venta.webpay_payment_status = ''
            venta.webpay_transaction_id = ''
            venta.fecha_compra = None  # ← Para evitar errores al reintentar
            venta.save()

            # Limpiar sesión
            request.session.pop('tipo_entrega', None)
            request.session.pop('direccion_despacho', None)

            mensaje = "❌ Pago rechazado"

    except Exception as e:
        return HttpResponse(f"<b>Error al procesar la transacción:</b> {e}")

    return render(request, 'carro_compras/webpay_respuesta.html', {
        'mensaje': mensaje,
        'venta': venta,
        'response': response
    })





@login_required
def ver_boleta(request, venta_id):
    venta = get_object_or_404(Venta, id=venta_id)

    # Solo el dueño o un admin puede verla
    if request.user != venta.id_usuario and not request.user.is_staff:
        return HttpResponseForbidden("No tienes permiso para ver esta boleta.")

    detalles = Detalle.objects.filter(id_venta=venta)
    return render(request, 'carro_compras/boleta.html', {
        'venta': venta,
        'detalles': detalles
    })

#############

@csrf_exempt
@login_required
def vista_retiros(request):
    from .models import Venta
    mensaje = None

    if request.method == 'POST':
        venta_id = request.POST.get('venta_id')
        rut_ingresado = request.POST.get('rut')
        venta = get_object_or_404(Venta, id=venta_id, tipo_entrega='retiro', estado_entrega='pendiente')

        if rut_ingresado == venta.id_usuario.rut:
            venta.estado_entrega = 'completado'
            venta.save()
            mensaje = {'tipo': 'success', 'texto': f"✅ Retiro confirmado para Boleta N°{venta.id}"}
        else:
            mensaje = {'tipo': 'danger', 'texto': f"❌ RUT incorrecto para Boleta N°{venta.id}"}

    retiros_pendientes = Venta.objects.filter(tipo_entrega='retiro', estado_entrega='pendiente')
    retiros_realizados = Venta.objects.filter(tipo_entrega='retiro', estado_entrega='completado')

    return render(request, 'carro_compras/retiros.html', {
        'ventas': retiros_pendientes,
        'realizados': retiros_realizados,
        'mensaje': mensaje
    })

@csrf_exempt
@login_required
def vista_despachos(request):
    from .models import Venta
    mensaje = None

    if request.method == 'POST':
        venta_id = request.POST.get('venta_id')
        venta = get_object_or_404(Venta, id=venta_id, tipo_entrega='despacho', estado_entrega='pendiente')
        venta.estado_entrega = 'completado'
        venta.save()
        mensaje = {'tipo': 'success', 'texto': f"✅ Despacho marcado como completado para Boleta N°{venta.id}"}

    pendientes = Venta.objects.filter(tipo_entrega='despacho', estado_entrega='pendiente')
    completados = Venta.objects.filter(tipo_entrega='despacho', estado_entrega='completado')

    return render(request, 'carro_compras/despachos.html', {
        'pendientes': pendientes,
        'completados': completados,
        'mensaje': mensaje
    })

@login_required
def mi_historial_compras(request):
    ventas = Venta.objects.filter(id_usuario=request.user, estado_venta='pagado').order_by('-fecha_compra')

    for venta in ventas:
        venta.detalles_list = venta.detalles.all()  # ← relación desde related_name

    return render(request, 'carro_compras/mi_historial.html', {'ventas': ventas})

@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_historial_ventas(request):
    ventas = Venta.objects.filter(estado_venta='pagado').order_by('-fecha_compra')
    serializer = VentaSerializer(ventas, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def api_mis_compras(request):
    if not request.user.is_authenticated:
        return Response({'detail': 'No autenticado'}, status=401)

    ventas = Venta.objects.filter(id_usuario=request.user, estado_venta='pagado').order_by('-fecha_compra')
    serializer = VentaSerializer(ventas, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_retiros(request):
    retiros = Venta.objects.filter(tipo_entrega='retiro').order_by('-fecha_compra')
    serializer = VentaSerializer(retiros, many=True)
    return Response(serializer.data)

# Confirmar retiro (admin)
@api_view(['POST'])
@permission_classes([IsAdminUser])
def api_confirmar_retiro(request, venta_id):
    rut = request.data.get('rut')
    venta = get_object_or_404(Venta, id=venta_id, tipo_entrega='retiro', estado_entrega='pendiente')

    if rut != venta.id_usuario.rut:
        return Response({'detail': '❌ RUT incorrecto'}, status=400)

    venta.estado_entrega = 'completado'
    venta.save()
    return Response({'mensaje': f"✅ Retiro confirmado para la venta #{venta.id}"})

@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_despachos(request):
    despachos = Venta.objects.filter(tipo_entrega='despacho').order_by('-fecha_compra')
    serializer = VentaSerializer(despachos, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAdminUser])
def api_confirmar_despacho(request, venta_id):
    venta = get_object_or_404(Venta, id=venta_id, tipo_entrega='despacho', estado_entrega='pendiente')
    venta.estado_entrega = 'completado'
    venta.save()
    return Response({'mensaje': f"✅ Despacho confirmado para la venta #{venta.id}"})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_boleta(request, id):
    venta = get_object_or_404(Venta, id=id)

    # Seguridad: solo el dueño o un admin puede verla
    if request.user != venta.id_usuario and not request.user.is_staff:
        return Response({'detail': 'No autorizado'}, status=403)

    serializer = VentaSerializer(venta)
    return Response(serializer.data)