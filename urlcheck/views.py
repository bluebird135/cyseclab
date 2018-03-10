from django.shortcuts import render
from django.shortcuts import render
from django.core.exceptions import *

from django.views.generic.base import TemplateView
from django.contrib import messages
from django.shortcuts import redirect

# Sslyze check
from . import urlcheck

class IndexView(TemplateView):
    template_name = 'index.html'

results = dict()
descriptions = dict()
robotdesc = "The Return Of Bleichenbacher's Oracle Threat, or ROBOT for short, is a vulnerability that allows performing RSA decryption and signing operations with the private key of a TLS server. "
robotdesc += "In 1998, Daniel Bleichenbacher discovered that the error messages given by SSL servers for errors in the PKCS #1 v1.5 padding allowed an adaptive-chosen ciphertext attack; "
robotdesc += "this attack fully breaks the confidentiality of TLS when used with RSA encryption. With some slight modifications the vulnerability can still be used today against many HTTPS hosts in todays internet. "
robotdesc += "For more information visit https://robotattack.org/"

heartbleeddesc = "Heartbleed is a security bug in the OpenSSL cryptography library. Since it is commonly used for the implementation in Transport Layer Security (TLS), the bug can affect many webservers. "
heartbleeddesc += "It was introduced in the software in 2012 and publicly disclosed and patched in April of 2014 and consists of an buffer over-read in the implementation "
heartbleeddesc += "of the TLS heartbeat extension due to improper input validation. For more information visit http://heartbleed.com/"

drowndesc = "The DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) attack is a cross-protocol bug that attacks servers supporting modern TLS procotols by using their support for deprecated and insecure protocols like SSLv2. "
drowndesc += "If the protocols share the same public key credentials, as is the normal case, an attacker can attack the SSLv2 connection and decrypt captured handshakes of TLS connections"
drowndesc += "For more information visit https://drownattack.com/"

descriptions["ROBOT"] = robotdesc
descriptions["HEARTBLEED"] = heartbleeddesc
descriptions["DROWN"] = drowndesc

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
            context_dict = {'errorMessage': str(e)}
            return render(request, 'index.html', context_dict)

        context = super(ResultView, self).get_context_data()

        resultList = []
        for attack in results.keys():
            resultList.append([attack, results[attack], descriptions[attack]])

        context_dict = {'resultList': resultList, 'hostURL': url}
        return render(request, 'base.html', context_dict)
