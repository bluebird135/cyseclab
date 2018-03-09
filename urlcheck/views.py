from django.shortcuts import render
from django.shortcuts import render
from django.shortcuts import HttpResponse
from django.core.exceptions import *

# import own
#from . import checker

def search(request):
    if request.method == 'POST':
        search_id = request.POST.get('textfield', None)
        try:
            #user = checker.check(search_id)
            print(user)
            #do something with user
            html = user
            return HttpResponse(html)
        except Exception:
            return HttpResponse("no such user")
    else:
        return render(request, 'index.html')
