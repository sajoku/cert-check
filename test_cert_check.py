#!/usr/bin/env python3

import cryptography
import unittest

from cert_check.cert_check import CertChecker


class CertCheckerTests(unittest.TestCase):

    def setUp(self):
        domain = 'https://google.com/'
        self.checker = CertChecker(domain)

    def test_get_domain(self):
        test_data = 'google.com'
        # test case with the scheme
        self.assertEqual(test_data, self.checker.domain)
        # test case without scheme
        domain = 'google.com'
        checker = CertChecker(domain)
        self.assertEqual(test_data, checker.domain)

    def test_get_content(self):
        self.assertTrue(isinstance(
            self.checker.content,
            cryptography.hazmat.backends.openssl.x509._Certificate
        ))
