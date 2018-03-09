from django.urls import path

from . import views

urlpatterns = [
    path('checkurl/', views.checkurl, name='checkurl'),
]
