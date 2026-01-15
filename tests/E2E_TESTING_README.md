# Running End2End LifeSaver Tests

In order to be able to run those tests you need to have a local keystone instance running on your machine. the following steps will describe how to set everything up.

> Please follow the guide in the [Keystone repository](https://github.com/sapcc/keystone/blob/stable/2025.1-m3/LocalDeployment.md):

When you are done with the guide, you need to replace the keystone extension
dependency to point to the local repository you want to test.

**point keystone-extensions to the local repository:**
change **`custom-requirements.txt`**
your branch could be different.
```
git+https://github.com/sapcc/keystone-extensions.git@stable/2025.1-m3#egg=keystone-extensions
# to:
-e /Path/to/keystone-extensions/
```

**running the E2E Tests:**
while keystone local instance is running move to the **keystone-extensions** repository and execute:
```
python -m unittest tests.test_lifesaver_e2e -v 
```
of course you also need to create a virtual environment and install python dependencies before that.

this would be a correct output:
```
 Keystone is running at http://localhost:8000/v3
Testing with user: admin@Default
/Users/I761196/.local/share/uv/python/cpython-3.10.16-macos-aarch64-none/lib/python3.10/unittest/suite.py:166: ResourceWarning: unclosed <socket.socket fd=3, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0, laddr=('127.0.0.1', 61416), raddr=('127.0.0.1', 11211)>
  setUpClass()
ResourceWarning: Enable tracemalloc to get the object allocation traceback
test_credit_refill_over_time (tests.test_lifesaver_e2e.TestLifesaverE2E)
Test that credits refill over time allowing requests again ...
======================================================================
TEST: Credit refill over time
======================================================================

Phase 1: Exhausting credits for user test_refill_user_1767705102...
[+] Rate limited after 3 attempts

Phase 2: Waiting 70 seconds for credit refill...
(This tests that credits are actually refilled over time)
  70 seconds remaining...
  60 seconds remaining...
  50 seconds remaining...
  40 seconds remaining...
  30 seconds remaining...
  20 seconds remaining...
  10 seconds remaining...

Phase 3: Testing if credits have been refilled...
  Response status: 401
[+] Credits refilled! Now getting 401 (auth failed) instead of 429
This means rate limiting was lifted after credit refill
ok
test_rate_limiting_across_auth_methods (tests.test_lifesaver_e2e.TestLifesaverE2E)
Test that rate limiting works for all authentication methods ...
======================================================================
TEST: Rate limiting across different authentication methods
======================================================================

Preparing test data...
  [Token Helper] Created and revoked token: gAAAAABpXQpVYL20mMds...
  [Token Helper] Created revoked token: gAAAAABpXQpVbbsg0WPR...
  [Token Helper] Created valid auth token: gAAAAABpXQpVMWpGYgiX...
  [App Cred Helper] Using user_id: 786c5d9c6dfe4dd2a08d8156ffaa68e7
  [App Cred Helper] Created app credential: ecf7a46aa4a94aef925a...
  [App Cred Helper] Expires at: 2026-01-06T13:12:55Z
  [App Cred Helper] Waiting 2 seconds for expiration...
  [App Cred Helper] App credential should now be expired!

Testing: password_auth_with_names
  Endpoint: http://localhost:8000/v3/auth/tokens
  Method: POST
Rate limited after 3 attempts (Status: 429)
Retry-After: 60 seconds

Testing: password_auth_with_ids
  Endpoint: http://localhost:8000/v3/auth/tokens
  Method: POST
Rate limited after 3 attempts (Status: 429)
Retry-After: 60 seconds

Testing: app_credential_auth
  Endpoint: http://localhost:8000/v3/auth/tokens
  Method: POST
Rate limited after 3 attempts (Status: 429)
Retry-After: 60 seconds

Testing: token_auth_post_body
  Endpoint: http://localhost:8000/v3/auth/tokens
  Method: POST
Rate limited after 3 attempts (Status: 429)
Retry-After: 60 seconds

Testing: token_auth_get_header
  Endpoint: http://localhost:8000/v3/auth/tokens
  Method: GET
Rate limited after 1 attempts (Status: 429)
Retry-After: 60 seconds

Testing: s3_credentials
  Endpoint: http://localhost:8000/v3/s3tokens
  Method: POST
Rate limited after 3 attempts (Status: 429)
Retry-After: 60 seconds

Testing: ec2_credentials
  Endpoint: http://localhost:8000/v3/ec2tokens
  Method: POST
Rate limited after 3 attempts (Status: 429)
Retry-After: 60 seconds
ok
test_environment_variables (tests.test_lifesaver_e2e.TestLifesaverE2ESetup)
Check that required environment variables are accessible ...
Using Keystone at: http://localhost:8000/v3
ok
test_keystone_is_accessible (tests.test_lifesaver_e2e.TestLifesaverE2ESetup)
Verify Keystone is running and accessible ... Keystone is accessible (status: 200)
ok

----------------------------------------------------------------------
Ran 4 tests in 76.065s

OK

```