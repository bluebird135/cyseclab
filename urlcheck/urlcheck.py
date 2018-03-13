# ssllyze imports
from __future__ import absolute_import
from __future__ import unicode_literals
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand
from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.robot_plugin import RobotScanCommand, RobotScanResultEnum
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, Sslv30ScanCommand
from sslyze.plugins.compression_plugin import CompressionScanCommand
# own imports

def check( hostname_user_input):
    try:
        print(u'hostname_user_input: '+hostname_user_input)
        server_info = ServerConnectivityInfo(hostname=hostname_user_input) #u'google.com'
        server_info.test_connectivity_to_server(network_timeout=10)
    except ServerConnectivityError as e:
    # Could not establish an SSL connection to the server
        print(u'EXCEPTION')
        raise RuntimeError(u'Error when connecting to {}: {}!'.format(hostname_user_input, e.error_msg))
    
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
    
    # BEAST
    
    # BREACH
    
    # POODLE
    # concurrent_scanner.queue_scan_command(server_info, Sslv30ScanCommand()) -> redundant
    
    # DROWN
    # concurrent_scanner.queue_scan_command(server_info, Sslv20ScanCommand()) -> redundant
    
    # Detecting deprecated/weak ciphers
    concurrent_scanner.queue_scan_command(server_info, Sslv20ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Sslv30ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv10ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv11ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv12ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv13ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, CompressionScanCommand())
    
    # Lucky13 (optional)


    # Process the results
    robot_txt = None
    heartbleed_txt = None
    drown_txt = None
    poodle_txt = None
    beast_txt = None
    compression_text = None
    potential_weak_ciphers = set()
    print(u'\nProcessing results...')
    for scan_result in concurrent_scanner.get_results():
    # Sometimes a scan command can unexpectedly fail (as a bug); it is returned as a PluginRaisedExceptionResult
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            continue
            raise RuntimeError(u'Scan command failed: {}'.format(scan_result.as_text()))
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
                robot_txt = 'Uknown - Received inconsistent results'

        elif isinstance(scan_result.scan_command, CompressionScanCommand):
            compression_text = "Vulnerable"
            result_compression = scan_result.compression_name
            #print("Offered Compressions: "+str(result_compression))
            if "None" == str(result_compression):
                compression_text = "Not vulnerable"

        # Process Heartbleed    
        elif isinstance(scan_result.scan_command, HeartbleedScanCommand):
            result_heartbleed = scan_result.is_vulnerable_to_heartbleed
            heartbleed_txt = 'Not vulnerable'
            if result_heartbleed == True:
                heartbleed_txt = 'Vulnerable'
                
        # Process BEAST
        
        # Process BREACH (BREACH is an instance of the CRIME attack against HTTP compression (the use of gzip or DEFLATE data compression algorithms via the content-encoding option within HTTP)
        
        # Process POODLE (a server is vulerable to POOD if it supports SSLv3 with CBC in the list of accepted cipher suites + some TLS Versions which don't enforce padding rules (how to test?-> https://github.com/exploresecurity/test_poodle_tls/blob/master/test_poodle_tls.py)
        elif isinstance(scan_result.scan_command, Sslv30ScanCommand):
            poodle_txt = 'Not vulnerable'
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)
                if 'CBC' in cipher.name:
                    poodle_txt = 'Vulnerable'
                               
        
        # Process DROWN (a server is vulnerable to DROWN if it allows SSLv2 connections) Ref = https://drownattack.com/
        elif isinstance(scan_result.scan_command, Sslv20ScanCommand):
            drown_txt = 'Not vulnerable'
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)
                drown_txt = 'Vulnerable'

                
        # Collect deprecated/weak ciphers - NEED TO COMBINE WITH POODLE/DROWN/...
        # Ref: https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html#module-sslyze.plugins.openssl_cipher_suites_plugin
                
        elif isinstance(scan_result.scan_command, Tlsv10ScanCommand):
            beast_txt = "Not vulnerable"
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)
                beast_txt = "Vulnerable"

        elif isinstance(scan_result.scan_command, Tlsv11ScanCommand):
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)

        elif isinstance(scan_result.scan_command, Tlsv12ScanCommand):
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)

        elif isinstance(scan_result.scan_command, Tlsv13ScanCommand):
            for cipher in scan_result.accepted_cipher_list:
                potential_weak_ciphers.add(cipher.name)
        
        # Process Lucky13 (optional)
    
    # Process weak ciphers
    weak_ciphers = getWeakCiphers(potential_weak_ciphers)
    print("potential_weak_ciphers:")
    print(potential_weak_ciphers)
    print("\nweak_ciphers:")
    print(weak_ciphers)

    
    res = dict()
    #res["host"] = str(hostname_user_input)
    res["ROBOT"] = str(robot_txt)
    res["HEARTBLEED"] = str(heartbleed_txt)
    res["DROWN"] = str(drown_txt)
    res["POODLE"] = str(poodle_txt)
    res["BEAST"] = str(beast_txt)
    res["WEAKCIPHERS"] = 'Not vulnerable' if len(weak_ciphers) == 0 else '\n'.join(str(s) for s in weak_ciphers)
    res["CRIME"] = str(compression_text)
    return res


# TODO Order by appearance in cipher_suite_name for better performance
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

