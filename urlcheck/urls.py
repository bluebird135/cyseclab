from django.urls import path

from . import views

urlpatterns = [
    #path('checkurl/', views.checkurl, name='checkurl'),
    path('checkurl/', views.ResultView.as_view(), name='checkurl'),
]
