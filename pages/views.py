# pages/views.py
from django.shortcuts import render
from django.shortcuts import HttpResponse
from django.core.exceptions import *

# import own
#from . import checker


def index(request):
    return render(request, 'index.html')
