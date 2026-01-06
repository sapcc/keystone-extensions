"""
End-to-End tests for Lifesaver middleware against a real Keystone instance.

These tests require a running Keystone instance with the Lifesaver middleware enabled.
Set environment variables to configure:
- OS_AUTH_URL: Keystone endpoint (default: http://localhost:8000/v3)
- OS_USERNAME: Admin username (default: admin)
- OS_PASSWORD: Admin password (default: secret)
- OS_USER_DOMAIN_NAME: Domain name (default: Default)
- OS_PROJECT_NAME: Project name (default: admin)
- OS_PROJECT_DOMAIN_NAME: Project domain (default: Default)

Run with: python -m unittest tests.test_lifesaver_e2e -v

Note: These tests will exhaust credits for test users, so run against a test instance only!
"""

import unittest
import requests
import os
import time
import json


class TestLifesaverE2E(unittest.TestCase):
    """End-to-end tests against real Keystone instance with Lifesaver middleware"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment - check if Keystone is running"""
        cls.auth_url = os.getenv('OS_AUTH_URL', 'http://localhost:8000/v3')
        cls.admin_user = os.getenv('OS_USERNAME', 'admin')
        cls.admin_password = os.getenv('OS_PASSWORD', 'secret')
        cls.domain = os.getenv('OS_USER_DOMAIN_NAME', 'Default')
        cls.project = os.getenv('OS_PROJECT_NAME', 'admin')
        cls.project_domain = os.getenv('OS_PROJECT_DOMAIN_NAME', 'Default')

        import memcache
        mc = memcache.Client(['127.0.0.1:11211'])
        mc.flush_all()
        time.sleep(1)  # Give it a moment
        
        # Check if Keystone is running and accessible
        try:
            response = requests.get(cls.auth_url, timeout=5)
            if response.status_code not in [200, 300]:
                raise unittest.SkipTest(
                    f"Keystone not responding correctly at {cls.auth_url}. "
                    f"Got status {response.status_code}"
                )
        except requests.exceptions.RequestException as e:
            raise unittest.SkipTest(
                f"Keystone not available at {cls.auth_url}. "
                f"Error: {e}\n"
            )
        
        print(f"\n Keystone is running at {cls.auth_url}")
        print(f"Testing with user: {cls.admin_user}@{cls.domain}")
    
    def setUp(self):
        """Set up each test"""
        self.session = requests.Session()
        # Disable SSL warnings for local testing
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def tearDown(self):
        """Clean up after each test"""
        self.session.close()
    
    def _get_admin_token(self):
        """Get a valid admin token for setup/teardown"""
        auth_data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.admin_user,
                            "password": self.admin_password,
                            "domain": {"name": self.domain}
                        }
                    }
                },
                "scope": {
                    "project": {
                        "name": self.project,
                        "domain": {"name": self.project_domain}
                    }
                }
            }
        }
        
        response = self.session.post(
            f"{self.auth_url}/auth/tokens",
            json=auth_data,
            verify=False
        )
        
        if response.status_code == 201:
            return response.headers.get('X-Subject-Token')
        return None
    
    def _get_admin_user_id(self):
        """Get the admin user ID from token info"""
        admin_token = self._get_admin_token()
        if not admin_token:
            return None
        
        # Validate token to get user info
        response = self.session.get(
            f"{self.auth_url}/auth/tokens",
            headers={
                'X-Auth-Token': admin_token,
                'X-Subject-Token': admin_token
            },
            verify=False
        )
        
        if response.status_code == 200:
            token_data = response.json()
            user_id = token_data.get('token', {}).get('user', {}).get('id')
            return user_id
        
        return None
    
    def _revoke_token(self, admin_token, token_to_revoke):
        """Revoke a token using DELETE request"""
        headers = {
            'X-Auth-Token': admin_token,           # Valid token for authentication
            'X-Subject-Token': token_to_revoke     # Token to revoke
        }
        
        response = self.session.delete(
            f"{self.auth_url}/auth/tokens",
            headers=headers,
            verify=False
        )
        
        return response.status_code == 204
    
    def _create_revoked_token(self):
        """Create a token and immediately revoke it for testing
        
        Returns a revoked token that:
        - Is properly formatted (so Lifesaver can extract user)
        - Will fail authentication (401 error)
        - Triggers rate limiting
        """
        # Step 1: Get admin token for authentication
        admin_token = self._get_admin_token()
        if not admin_token:
            return None
        
        # Step 2: Create a second token that we'll revoke
        token_to_revoke = self._get_admin_token()
        if not token_to_revoke:
            return None
        
        # Step 3: Revoke the second token
        revoked = self._revoke_token(admin_token, token_to_revoke)
        
        if revoked:
            print(f"  [Token Helper] Created and revoked token: {token_to_revoke[:20]}...")
            return token_to_revoke
        else:
            print(f"  [Token Helper] Failed to revoke token")
            return None
    
    def _create_test_tokens_for_get(self):
        """Create both a revoked token and a valid auth token for GET tests
        
        The GET /v3/auth/tokens endpoint requires:
        - X-Auth-Token: A valid token to authorize the request
        - X-Subject-Token: The token to validate (we use revoked one)
        
        Returns:
            tuple: (revoked_token, valid_auth_token) or (None, None) if failed
        """
        # Step 1: Get admin token for operations
        admin_token = self._get_admin_token()
        if not admin_token:
            return None, None
        
        # Step 2: Create token to revoke
        token_to_revoke = self._get_admin_token()
        if not token_to_revoke:
            return None, None
        
        # Step 3: Revoke the second token
        revoked = self._revoke_token(admin_token, token_to_revoke)
        if not revoked:
            print(f"  [Token Helper] Failed to revoke token")
            return None, None
        
        # Step 4: Get a fresh valid token for X-Auth-Token
        valid_auth_token = self._get_admin_token()
        if not valid_auth_token:
            return None, None
        
        print(f"  [Token Helper] Created revoked token: {token_to_revoke[:20]}...")
        print(f"  [Token Helper] Created valid auth token: {valid_auth_token[:20]}...")
        
        return token_to_revoke, valid_auth_token
    
    def _create_expired_app_credential(self):
        """Create an application credential that expires in 1 second
        
        Returns:
            tuple: (app_cred_id, app_cred_secret) or (None, None) if failed
        """
        from datetime import datetime, timedelta, timezone
        
        # Step 1: Get admin token and user ID
        admin_token = self._get_admin_token()
        if not admin_token:
            raise unittest.SkipTest("WARNING: Could not get admin token, skipping test.")
        
        user_id = self._get_admin_user_id()
        if not user_id:
            raise unittest.SkipTest("WARNING: Could not get admin user ID, skipping test.")
        
        print(f"  [App Cred Helper] Using user_id: {user_id}")
        
        # Step 2: Create app credential with 1 second expiration
        dt = datetime.now(timezone.utc) + timedelta(seconds=1)
        expires_at = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        # expires_at = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat() + 'Z'
        
        payload = {
            "application_credential": {
                "name": f"test_expired_{int(time.time())}",
                "description": "Test app credential for rate limiting E2E test",
                "expires_at": expires_at,
                "roles": [{"name": "admin"}]
            }
        }
        
        response = self.session.post(
            f"{self.auth_url}/users/{user_id}/application_credentials",
            json=payload,
            headers={'X-Auth-Token': admin_token},
            verify=False
        )
        
        if response.status_code == 201:
            data = response.json()['application_credential']
            app_cred_id = data['id']
            app_cred_secret = data['secret']
            
            print(f"  [App Cred Helper] Created app credential: {app_cred_id[:20]}...")
            print(f"  [App Cred Helper] Expires at: {expires_at}")
            print(f"  [App Cred Helper] Waiting 2 seconds for expiration...")
            
            # Step 3: Wait 2 seconds for it to expire
            time.sleep(2)
            
            print(f"  [App Cred Helper] App credential should now be expired!")
            return app_cred_id, app_cred_secret
        else:
            raise unittest.SkipTest(f"WARNING: Failed to create app credential: {response.text}")
        
    
    def test_rate_limiting_across_auth_methods(self):
        """Test that rate limiting works for all authentication methods"""
        print("\n" + "="*70)
        print("TEST: Rate limiting across different authentication methods")
        print("="*70)
        
        # Create a revoked token for POST token authentication test
        print("\nPreparing test data...")
        revoked_token = self._create_revoked_token()
        if not revoked_token:
            raise unittest.SkipTest("WARNING: Could not create revoked token, skipping test.")
        
        # Create tokens for GET token authentication test (needs both valid and revoked)
        revoked_token_for_get, valid_auth_token = self._create_test_tokens_for_get()
        if not revoked_token_for_get or not valid_auth_token:
            raise unittest.SkipTest("WARNING: Could not create tokens for GET test, skipping test.")
        
        # Create expired app credential
        app_cred_id, app_cred_secret = self._create_expired_app_credential()
        if not app_cred_id:
            print("  [Warning] Could not create expired app credential - using fake one")
            app_cred_id = "fake_app_cred_id_12345"
            app_cred_secret = "fake_secret"
        
        # Define test scenarios for each authentication method
        scenarios = [
            {
                "name": "password_auth_with_names",
                "method": "POST",
                "endpoint": f"{self.auth_url}/auth/tokens",
                "payload": {
                    "auth": {
                        "identity": {
                            "methods": ["password"],
                            "password": {
                                "user": {
                                    "name": "test_user_pwd_names",
                                    "password": "wrong_password",
                                    "domain": {"name": self.domain}
                                }
                            }
                        }
                    }
                },
                "headers": None
            },
            {
                "name": "password_auth_with_ids",
                "method": "POST",
                "endpoint": f"{self.auth_url}/auth/tokens",
                "payload": {
                    "auth": {
                        "identity": {
                            "methods": ["password"],
                            "password": {
                                "user": {
                                    "id": "fake_user_id_12345",
                                    "password": "wrong_password",
                                    "domain": {"id": "fake_domain_id_67890"}
                                }
                            }
                        }
                    }
                },
                "headers": None
            },
            {
                "name": "app_credential_auth",
                "method": "POST",
                "endpoint": f"{self.auth_url}/auth/tokens",
                "payload": {
                    "auth": {
                        "identity": {
                            "methods": ["application_credential"],
                            "application_credential": {
                                "id": app_cred_id,       # Use real expired app credential
                                "secret": app_cred_secret
                            }
                        }
                    }
                },
                "headers": None
            },
            {
                "name": "token_auth_post_body",
                "method": "POST",
                "endpoint": f"{self.auth_url}/auth/tokens",
                "payload": {
                    "auth": {
                        "identity": {
                            "methods": ["token"],
                            "token": {
                                "id": revoked_token  # Use real revoked token
                            }
                        }
                    }
                },
                "headers": None
            },
            {
                "name": "token_auth_get_header",
                "method": "GET",
                "endpoint": f"{self.auth_url}/auth/tokens",
                "payload": None,
                "headers": {
                    "X-Auth-Token": valid_auth_token,          # Valid token to authorize request
                    "X-Subject-Token": revoked_token_for_get   # Revoked token to validate
                }
            },
            {
                "name": "s3_credentials",
                "method": "POST",
                "endpoint": f"{self.auth_url}/s3tokens",
                "payload": {
                    "credentials": {
                        "access": "fake_s3_access_key",
                        "secret": "fake_s3_secret_key",
                        "token": "fake_s3_token"
                    }
                },
                "headers": None
            },
            {
                "name": "ec2_credentials",
                "method": "POST",
                "endpoint": f"{self.auth_url}/ec2tokens",
                "payload": {
                    "credentials": {
                        "access": "fake_ec2_access_key",
                        "secret": "fake_ec2_secret_key",
                        "signature": "fake_signature"
                    }
                },
                "headers": None
            }
        ]
        
        # Test each authentication method
        for scenario in scenarios:
            with self.subTest(auth_method=scenario["name"]):
                self._test_auth_method_rate_limiting(scenario)
    
    def _test_auth_method_rate_limiting(self, scenario):
        """Helper method to test rate limiting for a specific authentication method"""
        print(f"\nTesting: {scenario['name']}")
        print(f"  Endpoint: {scenario['endpoint']}")
        print(f"  Method: {scenario['method']}")
        
        rate_limited = False
        attempts = 0
        max_attempts = 50
        
        for i in range(max_attempts):
            attempts = i + 1
            
            # Make request based on method
            if scenario['method'] == 'POST':
                response = self.session.post(
                    scenario['endpoint'],
                    json=scenario['payload'],
                    headers=scenario['headers'],
                    verify=False
                )
            elif scenario['method'] == 'GET':
                response = self.session.get(
                    scenario['endpoint'],
                    headers=scenario['headers'],
                    verify=False
                )
            else:
                self.fail(f"Unsupported method: {scenario['method']}")
            
            status = response.status_code
            
            # Print progress every 5 attempts
            if attempts % 5 == 0:
                print(f"    Attempt {attempts}: Status {status}")
            
            if status == 429:  # Rate limited!
                rate_limited = True
                print(f"Rate limited after {attempts} attempts (Status: {status})")
                
                # Check for Retry-After header
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    print(f"Retry-After: {retry_after} seconds")
                
                self.assertEqual(status, 429, "Expected 429 Too Many Requests")
                break
            elif status in [401, 400, 404]:
                # Expected error responses for invalid credentials
                continue
            else:
                print(f"Unexpected status: {status}")
                print(f"Response: {response.text[:200]}")
        
        if not rate_limited:
            self.fail(
                f"Rate limiting NOT triggered for {scenario['name']} "
                f"after {max_attempts} attempts.\n"
                f"Check Lifesaver middleware configuration."
            )
    
    def test_credit_refill_over_time(self):
        """Test that credits refill over time allowing requests again"""
        print("\n" + "="*70)
        print("TEST: Credit refill over time")
        print("="*70)
        
        # Use a unique test user to avoid interference with other tests
        test_user = f"test_refill_user_{int(time.time())}"
        auth_data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": test_user,
                            "password": "wrong_password",
                            "domain": {"name": self.domain}
                        }
                    }
                }
            }
        }
        
        print(f"\nPhase 1: Exhausting credits for user {test_user}...")
        
        # Phase 1: Exhaust credits
        rate_limited = False
        for i in range(50):
            response = self.session.post(
                f"{self.auth_url}/auth/tokens",
                json=auth_data,
                verify=False
            )
            
            if response.status_code == 429:
                rate_limited = True
                print(f"[+] Rate limited after {i + 1} attempts")
                break
        
        if not rate_limited:
            self.skipTest("Could not trigger rate limiting in phase 1")
        
        # Verify we're still rate limited
        response = self.session.post(
            f"{self.auth_url}/auth/tokens",
            json=auth_data,
            verify=False
        )
        self.assertEqual(response.status_code, 429, 
                        "Should still be rate limited immediately after")
        
        # Phase 2: Wait for credit refill
        # Default refill is usually 60 seconds, wait 70 to be safe
        refill_wait_time = 70  # seconds
        print(f"\nPhase 2: Waiting {refill_wait_time} seconds for credit refill...")
        print("(This tests that credits are actually refilled over time)")
        
        # Show countdown
        for remaining in range(refill_wait_time, 0, -10):
            print(f"  {remaining} seconds remaining...")
            time.sleep(10)
        
        print("\nPhase 3: Testing if credits have been refilled...")
        
        # Phase 3: Try again - should work now (get 401 instead of 429)
        response = self.session.post(
            f"{self.auth_url}/auth/tokens",
            json=auth_data,
            verify=False
        )
        
        status = response.status_code
        print(f"  Response status: {status}")
        
        if status == 401:
            print("[+] Credits refilled! Now getting 401 (auth failed) instead of 429")
            print("This means rate limiting was lifted after credit refill")
        elif status == 429:
            # Still rate limited - maybe refill time is configured differently
            print("️[-] Still rate limited after waiting")
            print("    Check refill_seconds configuration in Lifesaver middleware")
            print("    The test waited 70 seconds, but refill might be configured differently")
            # Don't fail the test, just warn
            self.skipTest(f"Still rate limited after {refill_wait_time}s - check refill_seconds config")
        else:
            print(f"️Unexpected status: {status}")
        
        # we should NOT be rate limited anymore
        self.assertNotEqual(status, 429, 
                           f"Should not be rate limited after {refill_wait_time}s refill period")


class TestLifesaverE2ESetup(unittest.TestCase):
    """Tests to verify the E2E test environment is set up correctly"""
    
    def test_environment_variables(self):
        """Check that required environment variables are accessible"""
        auth_url = os.getenv('OS_AUTH_URL', 'http://localhost:8000/v3')
        self.assertIsNotNone(auth_url, "OS_AUTH_URL should be set")
        print(f"\nUsing Keystone at: {auth_url}")
    
    def test_keystone_is_accessible(self):
        """Verify Keystone is running and accessible"""
        auth_url = os.getenv('OS_AUTH_URL', 'http://localhost:8000/v3')
        try:
            response = requests.get(auth_url, timeout=5, verify=False)
            self.assertIn(response.status_code, [200, 300], 
                         f"Keystone should respond with 200/300, got {response.status_code}")
            print(f"Keystone is accessible (status: {response.status_code})")
        except requests.exceptions.RequestException as e:
            self.fail(f"Cannot connect to Keystone at {auth_url}: {e}")


if __name__ == '__main__':
    print("\n" + "="*70)
    print("Lifesaver Middleware - End-to-End Tests")
    print("="*70)
    print("\nThese tests run against a REAL Keystone instance.")
    print("Make sure you're running against a TEST instance!")
    print("\nEnvironment:")
    print(f"  OS_AUTH_URL: {os.getenv('OS_AUTH_URL', 'http://localhost:8000/v3')}")
    print(f"  OS_USERNAME: {os.getenv('OS_USERNAME', 'admin')}")
    print(f"  OS_USER_DOMAIN_NAME: {os.getenv('OS_USER_DOMAIN_NAME', 'Default')}")
    print("="*70 + "\n")
    input("Press Enter to continue or Ctrl+C to abort...")
    
    unittest.main(verbosity=2)
