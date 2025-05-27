from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),  # cuando entre a /
    path('panel-admin/', views.panel_administracion, name='panel_administracion'),
    path('contacto/', views.contacto, name='contacto'),  # ← agregado



]
