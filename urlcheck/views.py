from django.shortcuts import render
from django.shortcuts import render
from django.shortcuts import HttpResponse
from django.core.exceptions import *


from django.views.generic.base import TemplateView
from django.contrib import messages
from django.shortcuts import redirect

# Sslyze check
from . import urlcheck

class IndexView(TemplateView):
    template_name = 'index.html'

results = dict()

class ResultView(TemplateView):
    global results
    template_name = 'base.html'

    def get_context_data(self, **kwargs):
        context = super(ResultView, self).get_context_data(**kwargs)
        messages.info(self.request, 'hello http://example.com')
        for result in results:
            messages.info(self.request, str(result))
        return context

    def get(self, request):
        return redirect("/")
        context = super(ResultView, self).get_context_data()
        messages.info(self.request, 'hello http://example.com')
        return render(request, 'base.html')

    def post(self, request):
        print("In Post")
        url = request.POST.get('textfield', None)
        try:
            results = urlcheck.check(url)
        except Exception as e:
            import traceback
            print('Exception occured! '+str(e)+'\n')
            traceback.print_exc()
            return HttpResponse(str(e))

        context = super(ResultView, self).get_context_data()
        messages.info(self.request, "Analysis Result for: " + str(url))
        for attack in results.keys():
            messages.info(self.request, "Vulnerable to: "+str(attack)+" -> "+results[attack])
        return render(request, 'base.html')

def checkurl(request):
    if request.method == 'POST':
        url = request.POST.get('textfield', None)
        try:
            results = urlcheck.check(url)
            html = results
            #return HttpResponse(html)
            print('Analysis Result: ')
            print(str(html))
            return ResultView.as_view()(request)
        except Exception as e:
            import traceback
            print('Exception occured! '+str(e)+'\n')
            traceback.print_exc()
            return HttpResponse(str(e))
    else:
        return render(request, 'index.html')

def index(request):
    return render(request, 'base.html')