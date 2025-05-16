from django.contrib import admin
from .models import Venta, Detalle

@admin.register(Venta)
class VentaAdmin(admin.ModelAdmin):
    list_display = ('id', 'id_usuario', 'fecha_compra', 'estado_venta', 'tipo_entrega', 'estado_entrega', 'eliminado')
    list_filter = ('estado_venta', 'tipo_entrega', 'estado_entrega', 'eliminado')
    search_fields = ('id_usuario__username', 'id_usuario__rut')
    actions = ['marcar_como_eliminado', 'restaurar_venta']

    def get_queryset(self, request):
        # Solo muestra ventas no eliminadas por defecto
        qs = super().get_queryset(request)
        return qs.filter(eliminado=False)

    def marcar_como_eliminado(self, request, queryset):
        queryset.update(eliminado=True)
        self.message_user(request, "Ventas marcadas como eliminadas.")
    marcar_como_eliminado.short_description = "🗑️ Marcar como eliminadas"

    def restaurar_venta(self, request, queryset):
        queryset.update(eliminado=False)
        self.message_user(request, "Ventas restauradas.")
    restaurar_venta.short_description = "♻️ Restaurar ventas"

@admin.register(Detalle)
class DetalleAdmin(admin.ModelAdmin):
    list_display = ('id_venta', 'nombre_producto', 'cantidad_producto', 'precio_unitario', 'subtotal_venta')
    search_fields = ('nombre_producto',)
