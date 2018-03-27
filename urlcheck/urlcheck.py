# ssllyze imports
from __future__ import absolute_import
from __future__ import unicode_literals
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand
from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.robot_plugin import RobotScanCommand, RobotScanResultEnum
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, Sslv30ScanCommand
from sslyze.plugins.compression_plugin import CompressionScanCommand

import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID
from binascii import hexlify

# own imports
import collections
import re

def check( hostname_user_input):
    try:
        print(u'hostname_user_input: '+hostname_user_input)

        # Strip http(s)
        m = re.search('^(https?://)?(.*?)(/.*)?$', hostname_user_input)
        if m.group(2):
            hostname_user_input = m.group(2)
        else:
            raise RuntimeError(u'Please provide non-empty host name!')

        server_tester = ServerConnectivityTester(hostname_user_input)
        server_info = server_tester.perform(network_timeout=10)
    # Could not establish an SSL connection to the server
    except ServerConnectivityError as e:
        raise RuntimeError(u'Error when connecting to {}: {}!'.format(hostname_user_input, e.error_msg))
    # No SSL used
    except IOError as e:
        raise RuntimeError(u'Protocol does not use SSL/TLS!')
    
    # If the call to test_connectivity_to_server() returns successfully, the server_info is then ready to be used for scanning the server.
    
    # The ConcurrentScanner uses a pool of processes to run ScanCommands concurrently. 
    # It is very fast when scanning a large number of servers, and it has a dispatching mechanism to avoid DOS-ing a single server against which multiple ScanCommand are run at the same time.
    # The commands can be queued using the queue_scan_command() method, and the results can later be retrieved using the get_results() method:
    # Ref: https://nabla-c0d3.github.io/sslyze/documentation/running-scan-commands.html
    concurrent_scanner = ConcurrentScanner()
    
    # Put scans in queue - Put desired scans here
    # ROBOT
    concurrent_scanner.queue_scan_command(server_info, RobotScanCommand())
    
    # Heartbleed
    concurrent_scanner.queue_scan_command(server_info, HeartbleedScanCommand())
    
    # Detecting deprecated/weak ciphers
    concurrent_scanner.queue_scan_command(server_info, Sslv20ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Sslv30ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv10ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv11ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv12ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv13ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, CompressionScanCommand())

    # Process the results
    robot_txt = 'Scan could not be executed'
    heartbleed_txt = 'Scan could not be executed'
    drown_txt = 'Scan could not be executed'
    poodle_txt = 'Scan could not be executed'
    beast_txt = 'Scan could not be executed'
    compression_text = 'Scan could not be executed'
    lucky_text = 'Scan could not be executed'
    potential_weak_ciphers = set()

    print(u'\nProcessing results...')
    for scan_result in concurrent_scanner.get_results():
        # Sometimes a scan command can unexpectedly fail (as a bug); it is returned as a PluginRaisedExceptionResult
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            raise RuntimeError(u'Scan command failed: Scan could not be executed!')
            continue

        # Each scan result has attributes with the information you're looking for, specific to each scan command
        # All these attributes are documented within each scan command's module
        if isinstance(scan_result.scan_command, RobotScanCommand):
            result_enum = scan_result.robot_result_enum
            if result_enum == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE:
                robot_txt = 'Vulnerable - Strong oracle, a real attack is possible'

            elif result_enum == RobotScanResultEnum.VULNERABLE_WEAK_ORACLE:
                robot_txt = 'Vulnerable - Weak oracle, the attack would take too long'

            elif result_enum == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE:
                robot_txt = 'Not vulnerable'

            elif result_enum == RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED:
                robot_txt = 'Not vulnerable, RSA cipher suites not supported'

            elif result_enum == RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS:
                robot_txt = 'Unknown - Received inconsistent results'

        # Process CRIME
        elif isinstance(scan_result.scan_command, CompressionScanCommand):
            compression_text = "Vulnerable"
            result_compression = scan_result.compression_name
            if "None" == str(result_compression):
                compression_text = "Not vulnerable"

        # Process Heartbleed    
        elif isinstance(scan_result.scan_command, HeartbleedScanCommand):
            result_heartbleed = scan_result.is_vulnerable_to_heartbleed
            heartbleed_txt = 'Not vulnerable'
            if result_heartbleed == True:
                heartbleed_txt = 'Vulnerable'
                
        # Process POODLE
        elif isinstance(scan_result.scan_command, Sslv30ScanCommand):
            poodle_txt = 'Not vulnerable'
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)
                if 'CBC' in cipher.name:
                    poodle_txt = 'Vulnerable'
                    beast_txt = "Not mitigated on server-side"
                               
        
        # Process DROWN (a server is vulnerable to DROWN if it allows SSLv2 connections) Ref = https://drownattack.com/
        elif isinstance(scan_result.scan_command, Sslv20ScanCommand):
            drown_txt = 'Not vulnerable'
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)
                drown_txt = 'Vulnerable'
                if 'CBC' in cipher.name:
                    beast_txt = "Not mitigated on server-side"

                
        # Collect deprecated/weak ciphers
        elif isinstance(scan_result.scan_command, Tlsv10ScanCommand):
            beast_txt = "Not vulnerable"
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)
                if 'CBC' in cipher.name:
                    beast_txt = "Not mitigated on server-side"

        elif isinstance(scan_result.scan_command, Tlsv11ScanCommand):
            if lucky_text != 'Vulnerable':
                lucky_text = 'Not vulnerable'
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)
                if 'CBC' in cipher.name:
                    lucky_text = 'Vulnerable'

        elif isinstance(scan_result.scan_command, Tlsv12ScanCommand):
            if lucky_text != 'Vulnerable':
                lucky_text = 'Not vulnerable'
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)
                if 'CBC' in cipher.name:
                    lucky_text = 'Vulnerable'

        elif isinstance(scan_result.scan_command, Tlsv13ScanCommand):
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)
        
    
    # Process weak ciphers
    weak_ciphers = getWeakCiphers(potential_weak_ciphers)
    print("potential_weak_ciphers:")
    print(potential_weak_ciphers)
    print("\nweak_ciphers:")
    print(weak_ciphers)

    
    res = collections.OrderedDict()
    res["BEAST"] = str(beast_txt)
    res["CRIME"] = str(compression_text)
    res["DROWN"] = str(drown_txt)
    res["HEARTBLEED"] = str(heartbleed_txt)
    res["LUCKY13"] = str(lucky_text)
    res["POODLE"] = str(poodle_txt)
    res["ROBOT"] = str(robot_txt)
    res["WEAKCIPHERS"] = 'Not vulnerable' if len(weak_ciphers) == 0 else '\n'.join(str(s) for s in weak_ciphers)


    details = getCertiDetails(hostname_user_input, potential_weak_ciphers)
    return (res, details)


def getWeakCiphers(pot_weak_ciphers):
    weak_ciphers = set()
    for cipher in pot_weak_ciphers:
        if '_RC2_' in cipher:
            weak_ciphers.add(cipher)
        elif '_RC4_' in cipher:
            weak_ciphers.add(cipher)
        elif '_DES_' in cipher:
            weak_ciphers.add(cipher)
        elif '_3DES_' in cipher:
            weak_ciphers.add(cipher)
        elif 'NULL' in cipher:
            weak_ciphers.add(cipher)
        # Additional weak ciphers
        elif '_EXPORT_' in cipher:
            weak_ciphers.add(cipher)
        elif '_anon_' in cipher:
            weak_ciphers.add(cipher)
        elif '_MD5' in cipher:
            weak_ciphers.add(cipher)
        elif '_DSA_' in cipher:
            weak_ciphers.add(cipher)
    return weak_ciphers


def getCertiDetails(url, cipherlist):
    details = collections.OrderedDict()

    try:
        pem = ssl.get_server_certificate((url, 443))
        cert = x509.load_pem_x509_certificate(pem.encode('ascii'), default_backend())
    except Exception as e:
        details["Error"] = (u'Could not retrieve certificate details from {}!'.format(url))
        return details

    details["Common Name"] = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    details["Version"] = str(cert.version)
    details["Serial Number"] = str('{:x}'.format(cert.serial_number)).upper()

    issuer = "Common Name: " + cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value + "\n"
    issuer += "Organization Name: " + cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value + "\n"
    issuer += "Country Name: " + cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value + "\n"
    details["Issuer"] = str(issuer)

    subject = "Common Name: " + getCertiAttribute(cert, NameOID.COMMON_NAME) + "\n"
    subject += "Organization Name: " + getCertiAttribute(cert, NameOID.ORGANIZATION_NAME) + "\n"
    subject += "Country Name: " + getCertiAttribute(cert, NameOID.COUNTRY_NAME) + "\n"
    subject += "State or Province: " + getCertiAttribute(cert, NameOID.STATE_OR_PROVINCE_NAME) + "\n"
    subject += "Locality: " + getCertiAttribute(cert, NameOID.LOCALITY_NAME) + "\n"
    details["Subject"] = subject

    details["Not valid before"] = str(cert.not_valid_before)
    details["Not valid after"] = str(cert.not_valid_after)
    details["Public Key Info"] = str(type(cert.public_key()).__name__[1:] + " | Key size: "+ (str(cert.public_key().key_size) + " Bit"))
    details["Fingerprint (SHA-256)"] = str(hexlify(cert.fingerprint(hashes.SHA256())))[2:-1].upper()
    details["Fingerprint (SHA 1)"] = str(hexlify(cert.fingerprint(hashes.SHA1())))[2:-1].upper()

    sig = cert.signature_hash_algorithm
    details["Signature Hash Algorithm"] = str(sig.name.upper() + " | Digest size: " + str(sig.digest_size) + " | Block size: " + str(sig.block_size))
    #details["Signature Algorithm OID"] = str(cert.signature_algorithm_oid)

    details["Cipher Suite"] = '\n'.join(str(s) for s in cipherlist)
    return details

# Returns the specified attribute, or "(none)" if the attribute does not exist
def getCertiAttribute(cert, att):
    if len(cert.subject.get_attributes_for_oid(att)) > 0:
        return cert.subject.get_attributes_for_oid(att)[0].value
    return "(none)"
