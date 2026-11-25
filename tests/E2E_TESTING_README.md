# Lifesaver verification

## Unit and middleware tests

Run from this repository using the Keystone environment with this checkout
installed (`pip install --no-deps -e /path/to/keystone-extensions`):

```sh
python -m unittest discover -s tests -p test_lifesaver_logic.py
python -m unittest discover -s tests -p test_lifesaver.py
```

The middleware tests use an isolated in-memory CAS transport. They cover
competing deductions and initialization, admission/response separation,
early/late ownership, allowlists, cache failures, refill, JSON responses and
the early-rejection metric. The paired Keystone repository also exercises
the actual Flask/AuthContext/SQL path in `test_contrib_s3_core.S3LifesaverCore`.

## HTTP end-to-end tests

Use a dedicated Keystone test instance with the paired early-phase loader,
this extension checkout and Memcached. Configure Lifesaver with a positive
refill amount and positive 401/404 validation costs. Test subjects and their
domain must not be allowlisted. The caller account must be able to create
application credentials and invoke both S3 and EC2 validation APIs.

Set `OS_AUTH_URL`, `OS_USERNAME`, `OS_PASSWORD`, `OS_USER_DOMAIN_ID`,
`OS_PROJECT_NAME` and `OS_PROJECT_DOMAIN_ID` for that instance. The domain ID
defaults are `default`; user/project names default to `admin`. Then run:

```sh
python -m unittest discover -s tests -p test_lifesaver_e2e.py -v
```

Each scenario uses unique test subjects. The suite never flushes or directly
connects to Memcached, and deletes the application credential it creates.
S3/EC2 scenarios send a valid caller token and require missing-key **404**
responses before **429**; an authorization failure cannot satisfy the test.
The refill scenario checks recovery after the returned `Retry-After` delay.
`LIFESAVER_MAX_ATTEMPTS` defaults to 200 and can be raised for larger credit
budgets or slower test instances.

For load verification, use multiple Keystone workers sharing an isolated
cache. Send one fixed missing S3 access key with a valid caller token at
1,300 requests/s sustained and 2,300 requests/s in bursts, alongside valid
token creation, token validation and S3 traffic. Record HTTP status counts,
end-to-end latency, caller-token and credential/SQL calls, cache operations
and worker CPU. Early 429s bypass Watcher, so its latency metrics alone do
not cover this path. Also verify that a cache outage preserves downstream
responses and the defined fail-open behaviour.
