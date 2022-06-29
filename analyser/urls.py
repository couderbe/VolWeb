from django.urls import path
from . import views
urlpatterns = [
    path('', views.analyser, name='analyser'),
    path('rules/', views.rules_management, name='rules'),
    path('add_rule/', views.add_rule, name='add_rule'),
]