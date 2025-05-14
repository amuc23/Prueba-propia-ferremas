from django.urls import path
from . import views

urlpatterns = [
    # Path para renderizar la vista HTML del carrito
    path('carrito/', views.vista_carrito, name='vista_carrito'),
    
    # Path para gestionar el carrito (ver y crear)
    path('api/carrito/', views.gestionar_carrito, name='gestionar_carrito'),

    # Path para agregar productos al carrito
    path('api/carrito/agregar/', views.agregar_producto_carrito, name='agregar_producto_carrito'),
    
    # Path para actualizar la cantidad de productos en el carrito
    path('api/carrito/detalle/<int:detalle_id>/', views.actualizar_cantidad_producto, name='actualizar_cantidad_producto'),

    # Path para disminuir la cantidad de un producto en el carrito
    path('api/carrito/detalle/disminuir/<int:detalle_id>/', views.disminuir_cantidad_producto, name='disminuir_cantidad_producto'),

    path('api/webpay/iniciar/', views.iniciar_pago_webpay, name='iniciar_pago_webpay'),
    
    path('api/webpay/respuesta/', views.respuesta_pago_webpay, name='respuesta_pago_webpay'),
    
    path('historial-ventas/', views.vista_historial_ventas, name='historial_ventas'),

    path('boleta/<int:venta_id>/', views.ver_boleta, name='ver_boleta'),
    
    path('boleta/<int:venta_id>/descargar/', views.descargar_boleta_pdf, name='descargar_boleta'),


]
