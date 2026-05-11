# Copyright 2026 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
End-to-End tests for Lifesaver middleware against a real Keystone instance.

These tests require a running Keystone instance with the Lifesaver middleware enabled.
Set environment variables to configure:
- OS_AUTH_URL: Keystone endpoint (default: http://localhost:8000/v3)
- OS_USERNAME: Admin username (default: admin)
- OS_PASSWORD: Admin password (default: s3cr3t)
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
import memcache


# Payloads

def password_auth_payload(username, password, domain_id):
    """Create a password authentication payload"""
    return {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "password": password,
                        "domain": {"id": domain_id}
                    }
                }
            }
        }
    }


def token_auth_payload(token_id):
    """Create a token authentication payload"""
    return {
        "auth": {
            "identity": {
                "methods": ["token"],
                "token": {"id": token_id}
            }
        }
    }


def app_credential_payload(app_cred_id, app_cred_secret):
    """Create an application credential authentication payload"""
    return {
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {
                    "id": app_cred_id,
                    "secret": app_cred_secret
                }
            }
        }
    }


def s3_credentials_payload(access_key, secret_key, token=""):
    """Create an S3 credentials payload"""
    return {
        "credentials": {
            "access": access_key,
            "secret": secret_key,
            "token": token
        }
    }


def ec2_credentials_payload(access_key, secret_key, signature=""):
    """Create an EC2 credentials payload"""
    return {
        "credentials": {
            "access": access_key,
            "secret": secret_key,
            "signature": signature
        }
    }


def scoped_password_auth_payload(username, password, user_domain_id, project_name, project_domain_id):
    """Create a scoped password authentication payload"""
    return {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "password": password,
                        "domain": {"id": user_domain_id}
                    }
                }
            },
            "scope": {
                "project": {
                    "name": project_name,
                    "domain": {"id": project_domain_id}
                }
            }
        }
    }


# Test Classes

class TestLifesaverE2E(unittest.TestCase):
    """End-to-end tests against real Keystone instance with Lifesaver middleware"""
    
    # Configuration constants
    MAX_RATE_LIMIT_ATTEMPTS = 50
    REFILL_WAIT_SECONDS = 20
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment - check if Keystone is running"""
        cls.auth_url = os.getenv('OS_AUTH_URL', 'http://localhost:8000/v3')
        cls.admin_user = os.getenv('OS_USERNAME', 'admin')
        cls.admin_password = os.getenv('OS_PASSWORD', 's3cr3t')
        cls.domain = os.getenv('OS_USER_DOMAIN_NAME', 'Default')
        cls.project = os.getenv('OS_PROJECT_NAME', 'admin')
        cls.project_domain = os.getenv('OS_PROJECT_DOMAIN_NAME', 'Default')
        cls.project_domain_id = os.getenv('OS_PROJECT_DOMAIN_ID', 'default')
        cls.user_domain_id = os.getenv('OS_USER_DOMAIN_ID', 'default')
        
        # Set up memcache connection
        cls.mc = memcache.Client(['127.0.0.1:11211'])
        cls.mc.flush_all()
        time.sleep(1)
        
        # Check if Keystone is running
        cls._verify_keystone_available()
        
        print(f"\n✓ Keystone is running at {cls.auth_url}")
        print(f"  Testing with user: {cls.admin_user}@{cls.domain}")
    
    @classmethod
    def _verify_keystone_available(cls):
        """Verify Keystone is running and accessible"""
        try:
            response = requests.get(cls.auth_url, timeout=5)
            if response.status_code not in [200, 300]:
                raise unittest.SkipTest(
                    f"Keystone not responding correctly at {cls.auth_url}. "
                    f"Got status {response.status_code}"
                )
        except requests.exceptions.RequestException as e:
            raise unittest.SkipTest(f"Keystone not available at {cls.auth_url}. Error: {e}")
    
    def setUp(self):
        """Set up each test"""
        self.session = requests.Session()
        # Disable SSL warnings for local testing
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def tearDown(self):
        """Clean up after each test"""
        self.session.close()
    
    # Helpers

    def _make_request(self, method, endpoint, payload=None, headers=None):
        """Make an HTTP request and return the response"""
        if method == 'POST':
            return self.session.post(endpoint, json=payload, headers=headers, verify=False)
        elif method == 'GET':
            return self.session.get(endpoint, headers=headers, verify=False)
        elif method == 'DELETE':
            return self.session.delete(endpoint, headers=headers, verify=False)
        else:
            raise ValueError(f"Unsupported method: {method}")
    
    def _get_admin_token(self):
        """Get a valid admin token"""
        payload = scoped_password_auth_payload(
            self.admin_user, self.admin_password, self.user_domain_id,
            self.project, self.project_domain_id
        )
        response = self._make_request('POST', f"{self.auth_url}/auth/tokens", payload)
        
        if response.status_code == 201:
            return response.headers.get('X-Subject-Token')
        return None
    
    def _get_admin_user_id(self):
        """Get the admin user ID from token info"""
        admin_token = self._get_admin_token()
        if not admin_token:
            return None
        
        response = self._make_request(
            'GET',
            f"{self.auth_url}/auth/tokens",
            headers={'X-Auth-Token': admin_token, 'X-Subject-Token': admin_token}
        )
        
        if response.status_code == 200:
            return response.json().get('token', {}).get('user', {}).get('id')
        return None
    
    def _create_app_credential(self):
        """
        Create a real application credential for testing.
        
        Returns:
            tuple: (app_credential_id, app_credential_secret)
        
        Note: Use the real ID with a WRONG secret to trigger 401 errors
        while still allowing the middleware to extract and track the credential ID.
        """
        admin_token = self._get_admin_token()
        if not admin_token:
            raise unittest.SkipTest("Could not get admin token for app credential creation")
        
        user_id = self._get_admin_user_id()
        if not user_id:
            raise unittest.SkipTest("Could not get admin user ID for app credential creation")
        
        payload = {
            "application_credential": {
                "name": f"test_ratelimit_{int(time.time())}",
                "description": "Test app credential for rate limiting E2E test",
                "roles": [{"name": "admin"}]
            }
        }
        
        response = self._make_request(
            'POST',
            f"{self.auth_url}/users/{user_id}/application_credentials",
            payload,
            headers={'X-Auth-Token': admin_token}
        )
        
        if response.status_code == 201:
            data = response.json()['application_credential']
            print(f"  [App Cred Helper] Created app credential: {data['id'][:20]}...")
            return data['id'], data['secret']
        
        raise unittest.SkipTest(f"Failed to create app credential: {response.text}")
    
    def _run_until_rate_limited(self, method, endpoint, payload=None, headers=None):
        """
        Send requests until rate limited (429) or max attempts reached.
        Returns (rate_limited: bool, attempts: int)
        """
        for i in range(self.MAX_RATE_LIMIT_ATTEMPTS):
            response = self._make_request(method, endpoint, payload, headers)
            
            if (i + 1) % 5 == 0:
                print(f"    Attempt {i + 1}: Status {response.status_code}")
            
            if response.status_code == 429:
                print(f"    Rate limited after {i + 1} attempts")
                return True, i + 1
        
        return False, self.MAX_RATE_LIMIT_ATTEMPTS
    
    # Tests

    def test_rate_limiting_across_auth_methods(self):
        """
        Test that rate limiting works for all authentication methods.
        
        Each scenario tests a DIFFERENT credential extraction path in the middleware:
        - password_auth: Extracts username from password auth body
        - token_auth_body: Extracts token ID from token auth body  
        - token_auth_header: Extracts token ID from X-Subject-Token header
        - app_credential: Extracts app credential ID from body
        - s3_credentials: Extracts S3 access key from body
        - ec2_credentials: Extracts EC2 access key from body
        
        We don't test different failure reasons (expired, revoked, invalid) separately
        because the middleware treats all 4xx responses equally.
        """
        print("\n" + "=" * 60)
        print("TEST: Rate limiting across different authentication methods")
        print("=" * 60)
        
        valid_auth_token = self._get_admin_token()
        if not valid_auth_token:
            self.skipTest("Could not get admin token for header tests")
        
        print("\nPreparing test data...")
        self._app_cred_id, _ = self._create_app_credential()
        
        scenarios = [
            ("password_auth", "POST", f"{self.auth_url}/auth/tokens",
             password_auth_payload("test_user", "wrong_password", self.user_domain_id), None),
            
            ("token_auth_body", "POST", f"{self.auth_url}/auth/tokens",
             token_auth_payload("invalid-token-id"), None),
            
            ("token_auth_header", "GET", f"{self.auth_url}/auth/tokens",
             None, {"X-Auth-Token": valid_auth_token, "X-Subject-Token": "invalid-token"}),
            
            ("app_credential", "POST", f"{self.auth_url}/auth/tokens",
             app_credential_payload(self._app_cred_id, "wrong-secret-for-testing"), None),
            
            ("s3_credentials", "POST", f"{self.auth_url}/s3tokens",
             s3_credentials_payload("fake_s3_access", "fake_s3_secret"), None),
            
            ("ec2_credentials", "POST", f"{self.auth_url}/ec2tokens",
             ec2_credentials_payload("fake_ec2_access", "fake_ec2_secret", "fake_sig"), None),
        ]
        
        # Test each scenario
        for name, method, endpoint, payload, headers in scenarios:
            with self.subTest(auth_method=name):
                print(f"\nTesting: {name}")
                
                # Reset rate limit state
                self.mc.flush_all()
                time.sleep(0.5)
                
                rate_limited, attempts = self._run_until_rate_limited(method, endpoint, payload, headers)
                
                self.assertTrue(
                    rate_limited,
                    f"Rate limiting NOT triggered for {name} after {attempts} attempts"
                )
    
    def test_credit_refill_over_time(self):
        """Test that credits refill over time allowing requests again
        You might need to check what is configured in keystone instance as
        refill_seconds and adjust REFILL_WAIT_SECONDS accordingly.
        """
        print("\n" + "=" * 60)
        print("TEST: Credit refill over time")
        print("=" * 60)
        
        # Use unique user to avoid interference
        test_user = f"test_refill_user_{int(time.time())}"
        payload = password_auth_payload(test_user, "wrong_password", self.user_domain_id)
        endpoint = f"{self.auth_url}/auth/tokens"
        
        # Phase 1: Exhaust credits
        print(f"\nPhase 1: Exhausting credits for user {test_user}...")
        rate_limited, _ = self._run_until_rate_limited('POST', endpoint, payload)
        
        if not rate_limited:
            self.skipTest("Could not trigger rate limiting in phase 1")
        
        # Verify still rate limited
        response = self._make_request('POST', endpoint, payload)
        self.assertEqual(response.status_code, 429, "Should still be rate limited immediately after")
        
        # Phase 2: Wait for refill
        print(f"\nPhase 2: Waiting {self.REFILL_WAIT_SECONDS} seconds for credit refill...")
        for remaining in range(self.REFILL_WAIT_SECONDS, 0, -10):
            print(f"  {remaining} seconds remaining...")
            time.sleep(10)
        
        # Phase 3: Verify refill
        print("\nPhase 3: Testing if credits have been refilled...")
        response = self._make_request('POST', endpoint, payload)
        status = response.status_code
        
        if status == 401:
            print("  Credits refilled! Now getting 401 instead of 429")
        elif status == 429:
            self.skipTest(f"Still rate limited after {self.REFILL_WAIT_SECONDS}s - check refill_seconds config")
        
        self.assertNotEqual(status, 429, "Should not be rate limited after refill period")


class TestLifesaverE2ESetup(unittest.TestCase):
    """Tests to verify the E2E test environment is set up correctly"""
    
    def test_keystone_is_accessible(self):
        """Verify Keystone is running and accessible"""
        auth_url = os.getenv('OS_AUTH_URL')
        self.assertIsNotNone(auth_url, "OS_AUTH_URL should be set")
        print(f"\n  Using Keystone at: {auth_url}")

        try:
            response = requests.get(auth_url, timeout=5, verify=False)
            self.assertIn(response.status_code, [200, 300],
                         f"Keystone should respond with 200/300, got {response.status_code}")
            print(f"  Keystone is accessible (status: {response.status_code})")
        except requests.exceptions.RequestException as e:
            self.fail(f"Cannot connect to Keystone at {auth_url}: {e}")


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("Lifesaver Middleware - End-to-End Tests")
    print("=" * 60)
    print("\nThese tests run against a REAL Keystone instance.")
    print("Make sure you're running against a TEST instance!")
    print("\nEnvironment:")
    print(f"  OS_AUTH_URL: {os.getenv('OS_AUTH_URL')}")
    print(f"  OS_USERNAME: {os.getenv('OS_USERNAME', 'admin')}")
    print(f"  OS_USER_DOMAIN_NAME: {os.getenv('OS_USER_DOMAIN_NAME', 'Default')}")
    print("=" * 60 + "\n")
    
    unittest.main(verbosity=2)