import unittest
import os
import importlib.util

# Load the module directly from file path, bypassing forced
# package imports that would cause a need for unnecessary mocking.
module_path = os.path.join(
    os.path.dirname(__file__), 
    '..', 
    'cc', 
    'keystone', 
    'middleware', 
    'lifesaver_logic.py'
)
spec = importlib.util.spec_from_file_location("lifesaver_logic", module_path)
lifesaver_logic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifesaver_logic)


class TestExtractPasswordAuthCredentials(unittest.TestCase):
    """Test extracting credentials from password authentication"""
    
    def test_extracts_user_and_domain_by_name(self):
        class MockRequest:
            path = '/v3/auth/tokens'
            method = 'POST'
            json_body = {
                "auth": {
                    "identity": {
                        "password": {
                            "user": {
                                "name": "testuser",
                                "domain": {"name": "TestDomain"}
                            }
                        }
                    }
                }
            }
        
        request = MockRequest()
        user, domain = lifesaver_logic.extract_password_auth_credentials(request)
        
        self.assertEqual(user, "testuser")
        self.assertEqual(domain, "TestDomain")
    
    def test_extracts_user_and_domain_by_id(self):
        class MockRequest:
            path = '/v3/auth/tokens'
            method = 'POST'
            json_body = {
                "auth": {
                    "identity": {
                        "password": {
                            "user": {
                                "id": "user-123",
                                "domain": {"id": "domain-456"}
                            }
                        }
                    }
                }
            }
        
        request = MockRequest()
        user, domain = lifesaver_logic.extract_password_auth_credentials(request)
        
        self.assertEqual(user, "id-user-123")
        self.assertEqual(domain, "domain-456")


class TestExtractAppCredential(unittest.TestCase):
    """Test extracting application credentials"""
    
    def test_extracts_app_credential_id(self):
        class MockRequest:
            path = '/v3/auth/tokens'
            method = 'POST'
            json_body = {
                "auth": {
                    "identity": {
                        "application_credential": {
                            "id": "app-cred-789"
                        }
                    }
                }
            }

        request = MockRequest()
        result = lifesaver_logic.extract_app_credential(request)

        self.assertEqual(result, "ac-app-cred-789")
    

class TestExtractTokenId(unittest.TestCase):
    """Test extracting token IDs from requests"""
    
    def test_extracts_token_from_post_body(self):
        class MockRequest:
            path = '/v3/auth/tokens'
            method = 'POST'
            json_body = {
                "auth": {
                    "identity": {
                        "token": {"id": "test-token-abc"}
                    }
                }
            }
            headers = {}
        
        request = MockRequest()
        result = lifesaver_logic.extract_token_id(request)
        
        self.assertEqual(result, "test-token-abc")
    
    def test_extracts_token_from_get_headers(self):
        class MockRequest:
            path = '/v3/auth/tokens'
            method = 'GET'
            json_body = {}
            headers = {'X-Subject-Token': 'header-token-xyz'}
        
        request = MockRequest()
        result = lifesaver_logic.extract_token_id(request)
        
        self.assertEqual(result, "header-token-xyz")


class TestExtractS3Ec2Credentials(unittest.TestCase):
    """Test extracting S3/EC2 credentials"""
    
    def test_extracts_s3_credentials(self):
        class MockRequest:
            path = '/v3/s3tokens'
            method = 'POST'
            json_body = {"credentials": {"access": "s3-access-key-123"}}
        
        request = MockRequest()
        user, domain = lifesaver_logic.extract_s3_ec2_credentials(request)
        
        self.assertEqual(user, "s3creds-s3-access-key-123")
        self.assertEqual(domain, "unknown")
    
    def test_extracts_ec2_credentials(self):
        class MockRequest:
            path = '/v3/ec2tokens'
            method = 'POST'
            json_body = {"ec2Credentials": {"access": "ec2-access-key-456"}}
        
        request = MockRequest()
        user, domain = lifesaver_logic.extract_s3_ec2_credentials(request)
        
        self.assertEqual(user, "ec2creds-ec2-access-key-456")
        self.assertEqual(domain, "unknown")


class TestCalculateCost(unittest.TestCase):
    """Test cost calculation logic"""
    
    def test_no_cost_for_2xx_status(self):
        status_cost = {'default': 1, '401': 10}
        token_cost = {'default': 1, '401': 10}
        
        cost = lifesaver_logic.calculate_cost(200, 'SOME-USER', status_cost, token_cost)
        
        self.assertEqual(cost, 0)
    
    def test_404_for_token_user_uses_token_cost(self):
        status_cost = {'default': 1, '404': 0}
        token_cost = {'default': 1, '404': 10}
        
        cost = lifesaver_logic.calculate_cost(404, 'FTOKENCREDS-USER-123', status_cost, token_cost)
        
        self.assertEqual(cost, 10)
    
    def test_404_for_password_user_uses_status_cost(self):
        status_cost = {'default': 1, '404': 0}
        token_cost = {'default': 1, '404': 10}
        
        cost = lifesaver_logic.calculate_cost(404, 'PASSWORD-USER', status_cost, token_cost)
        
        self.assertEqual(cost, 0)
    
    def test_401_for_token_user(self):
        status_cost = {'default': 1, '401': 10}
        token_cost = {'default': 1, '401': 15}
        
        cost = lifesaver_logic.calculate_cost(401, 'FTOKENCREDS-USER', status_cost, token_cost)
        
        self.assertEqual(cost, 15)
    
    def test_unknown_status_uses_default(self):
        status_cost = {'default': 5}
        token_cost = {'default': 3}
        
        cost = lifesaver_logic.calculate_cost(418, 'PASSWORD-USER', status_cost, token_cost)
        
        self.assertEqual(cost, 5)
    
    def test_case_insensitive_ftokencreds_check(self):
        status_cost = {'default': 1, '404': 0}
        token_cost = {'default': 1, '404': 10}
        
        # Test lowercase
        cost = lifesaver_logic.calculate_cost(404, 'ftokencreds-user', status_cost, token_cost)
        self.assertEqual(cost, 10)


class TestShouldUpdateScoreMetadata(unittest.TestCase):
    """Test score metadata update detection"""
    
    def test_returns_true_when_credit_changed(self):
        class MockScore:
            credit = 50
            refill_time = 60
            refill_amount = 5
        
        score = MockScore()
        
        result = lifesaver_logic.should_update_score_metadata(score, 100, 60, 5)
        
        self.assertTrue(result)
    
    def test_returns_true_when_refill_time_changed(self):
        class MockScore:
            credit = 100
            refill_time = 30
            refill_amount = 5
        
        score = MockScore()
        
        result = lifesaver_logic.should_update_score_metadata(score, 100, 60, 5)
        
        self.assertTrue(result)
    
    def test_returns_true_when_refill_amount_changed(self):
        class MockScore:
            credit = 100
            refill_time = 60
            refill_amount = 3
        
        score = MockScore()
        
        result = lifesaver_logic.should_update_score_metadata(score, 100, 60, 5)
        
        self.assertTrue(result)
    
    def test_returns_false_when_nothing_changed(self):
        class MockScore:
            credit = 100
            refill_time = 60
            refill_amount = 5
        
        score = MockScore()
        
        result = lifesaver_logic.should_update_score_metadata(score, 100, 60, 5)
        
        self.assertFalse(result)


class TestExtractFromAuthenticationRequest(unittest.TestCase):
    """Test extracting user from authenticated request"""
    
    def test_extracts_user_from_request_headers(self):
        """Test extracting user and domain from HTTP headers"""
        class MockRequest:
            environ = {
                'KEYSTONE_AUTH_CONTEXT': True,
                'HTTP_X_USER_NAME': 'header-user',
                'HTTP_X_USER_DOMAIN_NAME': 'header-domain'
            }
        
        request = MockRequest()
        user, domain = lifesaver_logic.extract_from_authentication_request(request)
        
        self.assertEqual(user, 'header-user')
        self.assertEqual(domain, 'header-domain')
    
    def test_extracts_user_from_token_info(self):
        """Test extracting user and domain from token info when headers not present"""
        class MockRequest:
            environ = {
                'KEYSTONE_AUTH_CONTEXT': True,
                'keystone.token_info': {
                    'token': {
                        'user': {
                            'name': 'token-user',
                            'domain': {
                                'name': 'token-domain'
                            }
                        }
                    }
                }
            }
        
        request = MockRequest()
        user, domain = lifesaver_logic.extract_from_authentication_request(request)
        
        self.assertEqual(user, 'token-user')
        self.assertEqual(domain, 'token-domain')
    
    def test_prefers_headers_over_token_info(self):
        """Test that headers take precedence over token info"""
        class MockRequest:
            environ = {
                'KEYSTONE_AUTH_CONTEXT': True,
                'HTTP_X_USER_NAME': 'header-user',
                'HTTP_X_USER_DOMAIN_NAME': 'header-domain',
                'keystone.token_info': {
                    'token': {
                        'user': {
                            'name': 'token-user',
                            'domain': {
                                'name': 'token-domain'
                            }
                        }
                    }
                }
            }
        
        request = MockRequest()
        user, domain = lifesaver_logic.extract_from_authentication_request(request)
        
        self.assertEqual(user, 'header-user')
        self.assertEqual(domain, 'header-domain')
    
    def test_falls_back_to_token_info_when_headers_incomplete(self):
        """Test fallback to token info when headers have only partial data"""
        class MockRequest:
            environ = {
                'KEYSTONE_AUTH_CONTEXT': True,
                'HTTP_X_USER_NAME': 'header-user',
                # No domain in headers
                'keystone.token_info': {
                    'token': {
                        'user': {
                            'name': 'token-user',
                            'domain': {
                                'name': 'token-domain'
                            }
                        }
                    }
                }
            }
        
        request = MockRequest()
        user, domain = lifesaver_logic.extract_from_authentication_request(request)
        
        # NOTE: Due to the implementation logic, when domain is missing from headers,
        # it enters the token_info block which overwrites BOTH user and domain
        self.assertEqual(user, 'token-user')
        self.assertEqual(domain, 'token-domain')
    
    def test_returns_none_when_no_auth_context(self):
        """Test that None is returned when KEYSTONE_AUTH_CONTEXT is missing"""
        class MockRequest:
            environ = {
                'HTTP_X_USER_NAME': 'some-user',
                'HTTP_X_USER_DOMAIN_NAME': 'some-domain'
            }
        
        request = MockRequest()
        user, domain = lifesaver_logic.extract_from_authentication_request(request)
        
        self.assertIsNone(user)
        self.assertIsNone(domain)
    


class TestHashTokenId(unittest.TestCase):
    """Test the hash_token_id function"""
    
    def test_returns_consistent_hash(self):
        """Same input always produces the same output"""
        result1 = lifesaver_logic.hash_token_id('test-token', 'secret-key')
        result2 = lifesaver_logic.hash_token_id('test-token', 'secret-key')
        
        self.assertEqual(result1, result2)
    
    def test_different_tokens_produce_different_hashes(self):
        """Different token IDs produce different hashes"""
        result1 = lifesaver_logic.hash_token_id('token-1', 'secret-key')
        result2 = lifesaver_logic.hash_token_id('token-2', 'secret-key')
        
        self.assertNotEqual(result1, result2)
    
    def test_different_keys_produce_different_hashes(self):
        """Different secret keys produce different hashes"""
        result1 = lifesaver_logic.hash_token_id('test-token', 'key-1')
        result2 = lifesaver_logic.hash_token_id('test-token', 'key-2')
        
        self.assertNotEqual(result1, result2)
    
    def test_default_sha512_produces_128_char_hash(self):
        """SHA-512 (default) produces a 128-character hex digest"""
        result = lifesaver_logic.hash_token_id('test-token', 'secret-key')
        
        self.assertEqual(len(result), 128)
    
    def test_sha256_produces_64_char_hash(self):
        """SHA-256 produces a 64-character hex digest"""
        result = lifesaver_logic.hash_token_id('test-token', 'secret-key', hash_function='sha256')
        
        self.assertEqual(len(result), 64)
    
    def test_raises_error_when_secret_key_is_none(self):
        """Raises ValueError when secret key is None"""
        with self.assertRaises(ValueError):
            lifesaver_logic.hash_token_id('test-token', None)
    
    def test_raises_error_when_secret_key_is_empty(self):
        """Raises ValueError when secret key is empty string"""
        with self.assertRaises(ValueError):
            lifesaver_logic.hash_token_id('test-token', '')
    
    def test_returns_hex_string(self):
        """Returns a valid hexadecimal string"""
        result = lifesaver_logic.hash_token_id('test-token', 'secret-key')
        
        # Should only contain hex characters
        self.assertTrue(all(c in '0123456789abcdef' for c in result))


if __name__ == '__main__':
    unittest.main()
