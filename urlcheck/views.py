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
drowndesc += "If the protocols share the same public key credentials, as is the normal case, an attacker can attack the SSLv2 connection and decrypt captured handshakes of TLS connections."
drowndesc += " For more information visit https://drownattack.com/"

poodledesc = "The POODLE attack (which stands for Padding Oracle On Downgraded Legacy Encryption) is a man-in-the-middle exploit which takes advantage of Internet and security software clients' fallback to SSL 3.0 "
poodledesc += " If attackers successfully exploit this vulnerability, on average, they only need to make 256 SSL 3.0 requests to reveal one byte of encrypted messages."
poodledesc += " For more information visit https://www.us-cert.gov/ncas/alerts/TA14-290A"

weakciphersdesc = "In order to secure data that is being transferred, TLS/SSL makes use of one or more cipher suites. A cipher suite is a combination of authentication, encryption and message authentication code (MAC) algorithms, all of which are used during the negotiation of security settings for a TLS/SSL connection and the secure transfer of data."
weakciphersdesc += " For more information visit https://www.acunetix.com/blog/articles/tls-ssl-cipher-hardening/"

beastdesc = "The BEAST (Browser Exploit Against SSL/TLS) vulnerability exploits a flaw in TLS 1.0."
beastdesc += " It uses a weakness in cipher block chaining (CBC) that enables a man-in-the-middle attack to obtain and decrypt authentication tokens."

crimedesc = "CRIME (Compression Ratio Info-leak Made Easy) is a vulnerability in compressed HTTPS. "
crimedesc += "It is a security exploit against secret web cookies over connections using the HTTPS and SPDY protocols that also use data compression. "
crimedesc += "When used to recover the content of secret authentication cookies, it allows an attacker to perform session hijacking on an authenticated web session, allowing the launching of further attacks."

descriptions["ROBOT"] = robotdesc
descriptions["HEARTBLEED"] = heartbleeddesc
descriptions["DROWN"] = drowndesc
descriptions["POODLE"] = poodledesc
descriptions["WEAKCIPHERS"] = weakciphersdesc
descriptions["BEAST"] = beastdesc
descriptions["CRIME"] = crimedesc

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
            certiDetails = urlcheck.getCertiDetails(url)
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

        certiData = []
        for header in certiDetails.keys():
            certiData.append([header, certiDetails[header]])

        context_dict = {'resultList': resultList, 'hostURL': url, 'certiData': certiData}
        return render(request, 'base.html', context_dict)
