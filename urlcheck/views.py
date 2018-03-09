from django.shortcuts import render
from django.shortcuts import render
from django.shortcuts import HttpResponse
from django.core.exceptions import *

# Sslyze check
from . import urlcheck

def checkurl(request):
    if request.method == 'POST':
        url = request.POST.get('textfield', None)
        try:
            result = urlcheck.check(url)
            html = result
            return HttpResponse(html)
        except Exception as e:
            return HttpResponse(str(e))
    else:
        return render(request, 'index.html')
