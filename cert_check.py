#!/bin/env python3

import datetime
import logging
import nmap
import pytz
import requests
import socket
import ssl
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse as urlparser


class CertChecker:
    '''Verifies the TLS/SSL certificate of a website.'''
    # TODO: Implement SNI check: ssl.HAS_SNI
    # https://stackoverflow.com/questions/19145097/getting-certificate-chain-with-python-3-3-ssl-module

    logger = logging.getLogger('cbb.cert-check')
    logger.setLevel(logging.DEBUG)

    def __init__(self, url):
        # see also https://stackoverflow.com/a/7691293
        self.url = url
        self.domain = self._get_domain()
        self.content = None

    def check(self):
        '''Main public check function.'''
        self.logger.info('Testing connection ...')
        if not self._test_connection():
            return False

        # get certificate content
        self.content = self._get_content()
        self.logger.info('Initialising TLS/SSL certificate check ...')
        if not self.domain:
            return False

        # get Subject Alternative Names
        san_name = self._get_extensions()
#        print('san_name:', san_name)

        # get subject "Common Name"
        subj_name = self._verify_subject()
        if subj_name == 'nocn' and san_name:
            subj_name = True
#        else:
#            subj_name = False

#        print('subj_name:', subj_name)
        return all((
            self._verify_version(),
            self._verify_date(),
            san_name,
            subj_name,
#            self._verify_issuer(),
        ))

    def _get_domain(self):
        '''Extracts domain name from the URL.'''
        self.logger.info('Getting domain ...')
        parsed = urlparser(self.url)
        if parsed.netloc:
            domain = parsed.netloc
        else:
#            if parsed.path:
#                print('Ignoring following requests')
#                sys.exit(0)

            self.logger.warning('URL must start with scheme (http / https).')
            url = '//{0}'.format(self.url)
            parsed = urlparser(url)
            domain = parsed.netloc
            if not domain:
                self.logger.error(
                    'Error while parsing the URL. Check the format.')
                return

        self.logger.info('Domain: {0}'.format(domain))
        print(domain)
        return domain

    def _test_connection(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((self.domain, 443))
            self.logger.info('Connected to port 443.')
            return True
        except:
            print('Cannot connect to port 443.')
            self.logger.warning('Cannot connect to port 443.')
            return False

        s.close()

    def _get_content(self):
        '''Decrypts certificate and returns `Certificate` object.
        See https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object
        for more details.
        '''  # noqa: E501
        self.logger.info('Getting certificate ...')
        print('Getting certificate ...')
        # https://stackoverflow.com/a/16899645
        cert = ssl.get_server_certificate((self.domain, 443))
        bycert = cert.encode('utf-8')
        content = x509.load_pem_x509_certificate(bycert, default_backend())
#        self.logger.info(content)
        print('OK')
        self.logger.info('OK')
        return content

    def _verify_version(self):
        '''Verifies certificate version.'''
        self.logger.info('Verifying certificate version ...')
        print('Verifying certificate version ...')
        try:
            version = self.content.version
            self.logger.info('Version: {0}'.format(version))
            print('OK')
            return True
        except x509.InvalidVersion as ex:
            self.logger.warning('Invalid certificate version: {0}'.format(ex))
            print('Invalid certificate version: {0}'.format(ex))
            return

    def _verify_date(self):
        '''Verifies certificate date.'''
        self.logger.info('Verifying certificate dates ...')
        print('Verifying certificate dates ...')
        # get notBefore
        not_before = self.content.not_valid_before
        # get notAfter
        not_after = self.content.not_valid_after
        # check the cert
        if not_before <= datetime.datetime.utcnow() < not_after:
            self.logger.info('Dates - OK')
            print('OK')
            return True

        self.logger.warning('Certificate has expired: %s - %s'
                            % (not_before, not_after))
        print('Certificate has expired: %s - %s'
                            % (not_before, not_after))
        return

    # TODO
    def _verify_subject(self):
        self.logger.info('Verifying certificate subject ...')
        print('Verifying certificate subject ...')
        cn = False
        for attribute in self.content.subject:
            key = attribute.oid._name
            val = attribute.value
            self.logger.info('{0}: {1}'.format(key, val))
            print('{0}: {1}'.format(key, val))
            # check if domain name coinsides with the Common Name
            if key == 'commonName':
                cn = True
                if self.domain.lower() in val.lower():
                    self.logger.info(self.domain, val)
                    print('OK')
                    return True

        if not cn:
            print('No CN field in the certificate.')
            self.logger.warning('No CN field in the certificate.')
            return 'nocn'

        return False

    # TODO
    def _get_extensions(self):
        '''Gets data from extensions.'''
        print('Verifying certificate extensions ...')
        self.logger.info('Verifying certificate extensions ...')
        san = self.content.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
        san_list = san.value.get_values_for_type(x509.DNSName)
#        self.logger.info('SAN: {0}'.format(san_list))
#        print('SAN: {0}'.format(san_list))
        for name in san_list:
            if self.domain in name:
                self.logger.info('SAN verification successfull')
                print('SAN verification successfull')
                return True

        self.logger.warning('The domain name is missing in the SAN list')
        return False

    # TODO
    def _verify_issuer(self):
        # http://www.sos.ca.gov/administration/regulations/current-regulations/technology/digital-signatures/approved-certification-authorities/
        self.logger.info('Verifying certificate issuer ...')
        for attribute in self.content.issuer:
            key = attribute.oid._name
            val = attribute.value
            self.logger.info('{0}: {1}'.format(key, val))

    def _scan_ports(self):
        ''' Scans ports of the server.'''
        print('Scanning ports ...')
        self.logger.info('Scanning ports ...')
        nm = nmap.PortScanner()
        nm.scan(self.domain)
        print(nm)
        hosts = nm.all_hosts()
        print(hosts)
        ip = hosts[0]
        print(ip)
        try:
            serv_state = nm[ip].tcp(443)['state']
            if serv_state == 'up':
                print('Server is UP.')
                return True
            else:
                print('Server is not accessible.')
                return False
        except KeyError:
            print('Not an HTTPS domain.')
            return False
