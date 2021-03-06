from django.shortcuts import render
from django.shortcuts import render
from django.core.exceptions import *

from django.views.generic.base import TemplateView
from django.contrib import messages
from django.shortcuts import redirect

import collections

# Sslyze check
from . import urlcheck

class IndexView(TemplateView):
    template_name = 'index.html'

results = collections.OrderedDict()
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
beastdesc += " BEAST is purely a client-side vulnerability. The scans performed by this page examine therefore merely whether the webserver mitigates the risk by not using CBC to encrypt the messages. The main risk of a BEAST attack should however be addressed by the browser. Most major browsers have already implemented such steps."
beastdesc += " For more information vist https://blog.qualys.com/ssllabs/2013/09/10/is-beast-still-a-threat and read \"Here Come The ⊕ Ninjas\" by Thai Duong & Juliano Rizzo. May 13, 2011. http://nerdoholic.org/uploads/dergln/beast_part2/ssl_jun21.pdf"

crimedesc = "CRIME (Compression Ratio Info-leak Made Easy) is a vulnerability in compressed HTTPS. "
crimedesc += "It is a security exploit against secret web cookies over connections using the HTTPS and SPDY protocols that also use data compression. "
crimedesc += "When used to recover the content of secret authentication cookies, it allows an attacker to perform session hijacking on an authenticated web session, allowing the launching of further attacks."
crimedesc += " For more information visit https://media.blackhat.com/eu-13/briefings/Beery/bh-eu-13-a-perfect-crime-beery-wp.pdf"

luckydesc = "The Lucky Thirteen attack exploits a vulnerability in the TLS versions 1.1 and 1.2. It's a timing attack that is applicable due to a flaw in the TLS specification."
luckydesc += "The vulnerability allows a Man-in-the-Middle attacker to recover plaintext from a TLS connection that uses CBC-mode encryption."
luckydesc += " For more information visit http://www.isg.rhul.ac.uk/tls/Lucky13.html"

descriptions["ROBOT"] = robotdesc
descriptions["HEARTBLEED"] = heartbleeddesc
descriptions["DROWN"] = drowndesc
descriptions["POODLE"] = poodledesc
descriptions["WEAKCIPHERS"] = weakciphersdesc
descriptions["BEAST"] = beastdesc
descriptions["CRIME"] = crimedesc
descriptions["LUCKY13"] = luckydesc

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
            results, certiDetails = urlcheck.check(url)
        except Exception as e:
            import traceback
            print('Exception occured! '+str(e)+'\n')
            traceback.print_exc()
            context_dict = {'errorMessage': str(e)}
            return render(request, 'index.html', context_dict)

        context = super(ResultView, self).get_context_data()

        resultList = []
        for name, result in results.items():
            resultList.append([name, result, descriptions[name]])

        certiData = []
        for header, details in certiDetails.items():
            certiData.append([header, details])

        context_dict = {'resultList': resultList, 'hostURL': url, 'certiData': certiData}
        return render(request, 'base.html', context_dict)


class StatView(TemplateView):
        template_name = 'statistics.html'
