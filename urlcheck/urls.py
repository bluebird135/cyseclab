from django.urls import path

from . import views

urlpatterns = [
    #path('checkurl/', views.checkurl, name='checkurl'),
    path('checkurl/', views.ResultView.as_view(), name='checkurl'),
    path('', views.IndexView.as_view(template_name='templates/index.html'), name='checkurl'),
    
]
