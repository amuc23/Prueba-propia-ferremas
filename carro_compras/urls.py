from django.urls import path
from . import views
from django.views.generic import TemplateView

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
    
    path('historial-ventas/', TemplateView.as_view(template_name='carro_compras/historial_ventas.html'), name='historial_ventas'),


    path('boleta/<int:venta_id>/', views.ver_boleta, name='ver_boleta'),

    path('retiros/', TemplateView.as_view(template_name='carro_compras/retiros.html'), name='vista_retiros'),
    path('despachos/', TemplateView.as_view(template_name='carro_compras/despachos.html'), name='vista_despachos'),
    path('mis-compras/', TemplateView.as_view(template_name='carro_compras/mi_historial.html'), name='mi_historial_compras'),
    path('api/historial-ventas/', views.api_historial_ventas, name='api_historial_ventas'),
    path('api/mis-compras/', views.api_mis_compras, name='api_mis_compras'),
    path('api/retiros/', views.api_retiros, name='api_retiros'),
    path('api/retiros/confirmar/<int:venta_id>/', views.api_confirmar_retiro, name='api_confirmar_retiro'),
    path('api/despachos/', views.api_despachos, name='api_despachos'),
    path('api/despachos/confirmar/<int:venta_id>/', views.api_confirmar_despacho, name='api_confirmar_despacho'),
    path('api/boleta/<int:id>/', views.api_boleta, name='api_boleta'),







 
   
]
