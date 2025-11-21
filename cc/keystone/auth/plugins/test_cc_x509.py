import base64
import unittest
import urllib.parse
from OpenSSL import crypto

from .cc_x509 import parse_certificate

class TestParseCertificate(unittest.TestCase):
    pem_data = """MIIDFzCCAf+gAwIBAgIUUo3uRErHxc+83JX0JOKZUkOMLLMwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNTA3MTExMDIzMzFa
Fw0yNjA3MTExMDIzMzFaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsshnt9IqzS3WnizkLGrC2VUwn
pkfY7hNczQjXJTSaqaQQZT4oixT32XaySFHetJGYdX3ofgNY6dWLpZSFabBIDQ7U
yYqLegaWTAcd7jQiNZPqqcRs7ga+ZjXRiYbP5/XV802p9x3CZBRP2cs2PqDuDLbN
058e8VGhT0ZM9sU3wVymC9x8xVTGbs6XF+UuBxZ9Or1YBv4+v/3t5QsUucuXoD72
Iz05Ji6CEH5N88o+O2FdfhVrw9nblT74/HfLA1M2GlBmPZ7hB8g6SY/W+IQTxa21
A3DVmt3YZE7cqS5vATmMvZusXn6cW27gj00RY0uTMcWL4YK3uC06qkZZ2cBzAgMB
AAGjUzBRMB0GA1UdDgQWBBRV2Asz8DmQ4PqkXXWflMyB06ROpTAfBgNVHSMEGDAW
gBRV2Asz8DmQ4PqkXXWflMyB06ROpTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQCO0PqYhHbhHHIx6/Z5gpb1AsnM8jIWR9LPKL4dRAwhuyjNOxBT
YggT1Yg3OrPSPVDbSOO64i5MqFQpVUORkqClXgQOIDVjsc7Afz+zPR+ynfsr82W6
rjU7jYhkyQNyQGiosHab3dvnYez/ZUyk2EfpOYKr9C78kDKXuvetCvlQDDzPKKRX
EeEBG+SoQk2mwbudM+rZyVc1wM3Pa57N8hX4Rv+iBQ85WPuyeGjm/e9Ewpx10f2p
VXHNbWkx7sEu41tgVl+OjN1zpFSHEAQ8NetDBC9BrcWFnjZx0ipTlOWl4Jv4Xf6N
Da1dTVdWvf5PiMMpTslDOziEYSOSILKMTBTl"""
    pem_certificate = "\n".join([
        "-----BEGIN CERTIFICATE-----",
        pem_data,
        "-----END CERTIFICATE-----",
        "",
    ])

    def _assert_parse_certificate(self, cert):
        parsed_certificate = parse_certificate(cert)
        parsed_pem_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, parsed_certificate).decode()
        self.assertEqual(self.pem_certificate, parsed_pem_certificate)

    def test_urlencoded_pem(self):
        # ingress-nginx format
        cert = urllib.parse.quote(self.pem_certificate)
        self._assert_parse_certificate(cert)

    def test_b64encoded_pem_without_labels(self):
        # akamai format
        cert = base64.b64encode(self.pem_data.encode())
        self._assert_parse_certificate(cert)
