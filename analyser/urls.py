from django.urls import path
from . import views
urlpatterns = [
    path('', views.analyser, name='analyser'),
    path('get_process_info/', views.get_process_info, name='get_process_info'),
]
