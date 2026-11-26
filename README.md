# Converged Cloud Keystone Extensions

Provides a custom identity driver, auth plugins, lifesaver middleware and keystone-manage-extension cli for keystone.

The identity driver supports:

- usage of Microsoft Active Directory as identity provider
- optional authentication fallback against a outlook exchange web service
- optional outlook exchange web service password mirroring on AD auth failure
- merging of several user account status flags (IDM/HR, CAM) into one
 keystone user.enabled attribute

The keystone-manage-extension cli provides

- a extended bootstrap command that takes care of giving the bootstrap user domain admin permissions
- a repair_assignments command to do a emergency role assignment cleanup after AD objects have been deleted that still have references to them

The auth plugins provide:

 - Radius / SecurID authentication
 - Password authentication with optional password validation against EWS and mirroring the externally validated password to LDAP

The Lifesaver middleware contains repeated failures from misconfigured scripts
by rejecting requests from subjects that have depleted their failure credit.

## Installation

Install the python package into the keystone (virtual) environment

    pip install git+https://github.com/sapcc/keystone-extensions.git


### Identity Driver

Enable keystone's [domain specific drivers](http://docs.openstack.org/developer/keystone/configuration.html#domain-specific-drivers)
and configure one or more domains to use the **cc_ldap** driver (instead of the usual sql or ldap).

The driver extends the standard keystone LDAP driver, so all [configuration
options of the LDAP driver](http://docs.openstack.org/developer/keystone/configuration.html#configuring-the-ldap-identity-provider) also apply to the CC_AD driver.


### The cc_password, cc_radius and cc_x509 auth plugins

The Converged Cloud authentication specific implementations are contained in keystone authentication plugins.

To replace the default keystone password-, external- and totp auth plugins with the cc versions, you need to override the plugin implementation in keystone.conf.

To enable the plugins, specify in keystone.conf:

    [auth]
    password = cc_password
    totp = cc_radius
    external = cc_x509

    methods = password,token,totp

The cc_password plugin offers the cc specific password mirroring logic from GLOBAL AD, via a password verification hack against the Outlook External Web Service (EWS).
If the password validation against AD fails, it will try to verify the same password against EWS.
If that succeeds, it is assumed that a GLOBAL password update has taken place and the cc AD password of the user is updated with the new password.

The plugin offers the following configuration settings:

    [cc_password]
    url = <your outlook exchange external web service url>
    secure = <a boolean that indicates if the certificate of above URL should be verified>


To use the SecurID plugin, the Radius server details need to be configures in keystone.conf as well:

    [cc_radius]
    host = <your radius host>
    port = <the port number of the radius service on the host>    
    secret = <the shared secret>

Single sign on support for Converged Cloud keystone consumers via SSO certificate is supported by the cc_x509 authentication plugin.
It supports authentication by evaluating the x509 client certificate headers (HTTP_SSL_CLIENT_VERIFY and HTTP_SSL_CLIENT_CERT)in a request and validating its content.
The request should also contain an additional HTTP_X_USER_DOMAIN_ID or HTTP_X_USER_DOMAIN_ID header to indicate what Openstack domain should be used for the user validation.    
To use the cc_x509 plugin, it needs to be configured in keystone.conf:

    [cc_x509]
    user_domain_id_header = HTTP_X_USER_DOMAIN_ID
    user_domain_name_header = HTTP_X_USER_DOMAIN_NAME
    trusted_issuer = CN=some common name,O=any corporate,C=CountryCode


### The lifesaver middleware

Each subject starts with configurable credit, replenished by a fixed amount
at a fixed interval. Responses with status >= 400 deduct their configured
cost; successful responses are free. An exhausted subject receives HTTP 429
at admission until its next refill. `Retry-After` reports the remaining whole
seconds until that refill. Rejected requests do not spend credit or delay refill.

`status_cost` applies to ordinary user/API errors. `token_cost` applies to
`FTOKENCREDS-`, `S3CREDS-` and `EC2CREDS-` subjects. Thus missing S3/EC2 access
keys cost 10 credits by default while ordinary API resource-lookup 404s are free.
S3/EC2 subjects represent access keys, independently of the caller's service
token. Their domain is `UNKNOWN`; allowlisting the caller does not exempt the
credential subject.

The middleware is configured in keystone.conf:

    [lifesaver]
    enabled = true
    # the memcached host to use
    memcached = localhost
    # a csv list of allowlisted domains
    domain_allowlist = Default, tempest
    # a csv list of allowlisted users
    user_allowlist = admin, keystone, nova, neutron, cinder, glance, designate, barbican, dashboard, manila, swift
    # a csv list of blocklisted users
    #user_blocklist =
    # initial user credit
    initial_credit = 100
    # how often do we refill credit
    refill_seconds = 60
    # and with what amount
    refill_amount = 5
    # cost of each status
    status_cost = default:1,401:10,403:5,404:0,429:0
    # cost of token and S3/EC2 credential validation failures
    token_cost = default:1,401:10,403:5,404:10,429:0

The paired Keystone Flask middleware loader installs these phases:

```text
Request ID / size checks / URL normalization
  -> Lifesaver (phase=pre_auth)
  -> AuthContext
  -> Watcher
  -> Lifesaver (default phase=post_auth)
  -> API
```

The early phase owns canonical POST `/v3/s3tokens` and `/v3/ec2tokens` requests
with an extractable access key, including the `credential` and `ec2Credentials`
payload aliases. It checks the shared score before service-token validation
and accounts for the final response once. Other requests retain late,
authenticated-identity accounting. Admitted responses keep their original
status, headers and body even if concurrent failures exhaust the same score.

Keystone loaders that check the middleware instance's `phase` retain the single
authenticated filter with older extensions. Older Keystone loaders also remain
supported through the default late phase. Early rejection requires both the
updated loader and this extension; either can be upgraded first.

Scores are shared through Memcached. Positive charges use fresh `gets`/CAS
updates, with `add` for initialization, at most three attempts and a 100 ms
socket timeout. Cache misses, eviction, outages or persistent write contention
fail open. Concurrent requests already admitted may complete together; this
is a failure-credit budget rather than an exact requests-per-second limit.

Early rejections bypass Watcher. They emit the StatsD counter
`openstack_lifesaver.early_rejections_total` to the same local exporter
(`127.0.0.1:9125`). Prometheus exposes
`openstack_lifesaver_early_rejections_total` with only `endpoint`
(`s3tokens` or `ec2tokens`) and `reason` (`credit` or `blocklist`) labels.
Per-request rejection and credit diagnostics are DEBUG logs.
