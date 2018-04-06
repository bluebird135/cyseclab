from django.urls import path

from . import views

urlpatterns = [
    path('', views.IndexView.as_view(template_name='index.html'), name='index'),
    path('checkurl/', views.ResultView.as_view(), name='checkurl'),
    #path('statistics/', views.StatView.as_view(), name='statistics'),
]
