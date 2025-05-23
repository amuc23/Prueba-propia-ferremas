# Generated by Django 5.2 on 2025-05-16 22:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('carro_compras', '0005_alter_venta_estado_entrega_alter_venta_estado_venta_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='detalle',
            name='imagen_producto',
            field=models.URLField(blank=True, max_length=500, null=True),
        ),
        migrations.AddField(
            model_name='detalle',
            name='nombre_producto',
            field=models.CharField(default='Producto eliminado', max_length=200),
        ),
        migrations.AddField(
            model_name='detalle',
            name='precio_unitario',
            field=models.IntegerField(default=0),
        ),
    ]
