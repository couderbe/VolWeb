from django.urls import path
from . import views
urlpatterns = [
    path('', views.analyser, name='analyser'),
    path('detection/', views.detection, name='detection'),
]