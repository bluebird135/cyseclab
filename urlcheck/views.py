from django.shortcuts import render
from django.shortcuts import render
from django.shortcuts import HttpResponse
from django.core.exceptions import *


from django.views.generic.base import TemplateView
from django.contrib import messages

# Sslyze check
from . import urlcheck

class ResultView(TemplateView):
    template_name = 'templates/base.html'

    def get_context_data(self, **kwargs):
        context = super(ResultView, self).get_context_data(**kwargs)
        messages.info(self.request, 'hello http://example.com')

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
