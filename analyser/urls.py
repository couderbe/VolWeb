from django.urls import path
from . import views
urlpatterns = [
    path('', views.analyser, name='analyser'),
    path('rules/', views.rules_management, name='rules'),
    path('add_rule/', views.add_rule, name='add_rule'),
    path('delete_rule/', views.delete_rule, name='delete_rule'),
    path('toggle_rule/', views.toggle_rule, name='toggle_rule'),
    path('download_rule/', views.download_rule, name='download_rule'),
    path('virustotal_file/', views.virustotal_file, name='virustotal_file'),
    path('virustotal_process/', views.virustotal_process, name='virustotal_process'),
    path('virustotal_dll/', views.virustotal_dll, name='virustotal_dll'),
    path('clamav/', views.clamAV, name='clamav'),
    path('get_model_object/', views.get_model_object, name='get_model_object'),
]
