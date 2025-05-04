from django.urls import path
from . import views

urlpatterns = [
    path('usuarios/iniciosesion/', views.iniciosesion, name='iniciosesion'),  # cuando entre a /iniciosesion/
    path('usuarios/registro/', views.registro, name='registro'),

]