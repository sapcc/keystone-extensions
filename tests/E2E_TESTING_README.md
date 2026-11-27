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
python -m unittest discover -s tests -p test_lifesaver_e2e.py -v
```
of course you also need to create a virtual environment and install python dependencies before that.

## Verification for early S3/EC2 filtering

Use a dedicated instance with the updated Keystone loader and this extension.
Test subjects must not be allowlisted. S3/EC2 cases use a valid caller token and
require missing-key HTTP 404 responses before HTTP 429; permission errors cannot
satisfy the test. The suite uses unique subjects without flushing Memcached,
deletes its application credential, and checks refill after `Retry-After`.

For local logic and middleware tests, run in the Keystone environment with this
checkout installed:

```sh
python -m unittest discover -s tests -p test_lifesaver_logic.py
python -m unittest discover -s tests -p test_lifesaver.py
```

The paired Keystone tests in `keystone.tests.unit.test_lifesaver.S3LifesaverCore`
exercise the real Flask, AuthContext and SQL path with Memcached mocked.
Early rejections bypass Watcher, so its metrics do not cover that path.

The output below is an example. Timing depends on the Lifesaver configuration.
```
$ python -m unittest tests.test_lifesaver_e2e -v
test_credit_refill_over_time (tests.test_lifesaver_e2e.TestLifesaverE2E)
Test that credits refill over time allowing requests again ... ok
test_rate_limiting_across_auth_methods (tests.test_lifesaver_e2e.TestLifesaverE2E)
Test that rate limiting works for all authentication methods. ... ok
test_keystone_is_accessible (tests.test_lifesaver_e2e.TestLifesaverE2ESetup)
Verify Keystone is running and accessible ... ok

----------------------------------------------------------------------
Ran 3 tests in 26.017s

OK

✓ Keystone is running at http://localhost:8000/v3
Testing with user: admin@monsoon3

============================================================
TEST: Credit refill over time
============================================================

Phase 1: Exhausting credits for user test_refill_user_1778673567...
Rate limited after 3 attempts

Phase 2: Waiting 20 seconds for credit refill...
20 seconds remaining...
10 seconds remaining...

Phase 3: Testing if credits have been refilled...
Credits refilled! Now getting 401 instead of 429

============================================================
TEST: Rate limiting across different authentication methods
============================================================

Preparing test data...
[App Cred Helper] Created app credential: dc8520bc8b35440cb426...

Testing: password_auth
Rate limited after 3 attempts

Testing: token_auth_body
Rate limited after 3 attempts

Testing: token_auth_header
Rate limited after 3 attempts

Testing: app_credential
Rate limited after 3 attempts

Testing: s3_credentials
Rate limited after 3 attempts

Testing: ec2_credentials
Rate limited after 3 attempts

Using Keystone at: http://localhost:8000/v3
Keystone is accessible (status: 200)


```
