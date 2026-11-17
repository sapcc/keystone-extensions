# Converged Cloud Keystone Extensions

Provides a custom identity driver, auth plugins, policy checks, lifesaver middleware and keystone-manage-extension cli for keystone.

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

The lifesaver middleware protects against abusive requests and rejects requests from users that have depleted their credit.

## Installation

Install the python package into the keystone (virtual) environment

    pip install git+https://github.com/sapcc/keystone-extensions.git


### Identity Driver

Enable keystone's [domain specific drivers](http://docs.openstack.org/developer/keystone/configuration.html#domain-specific-drivers)
and configure one or more domains to use the **cc_ldap** driver (instead of the usual sql or ldap).

The driver extends the standard keystone LDAP driver, so all [configuration
options of the LDAP driver](http://docs.openstack.org/developer/keystone/configuration.html#configuring-the-ldap-identity-provider) also apply to the CC_AD driver.


### The cc_clearance policy check

`cc_clearance:recipient` checks whether a grant recipient is eligible for roles
outside a narrow allowlist. It is discovered through the `oslo.policy.rule_checks`
entry point; installing the updated package and referencing the check in policy
requires no Keystone source changes.

This prototype hardcodes the recipient identity domain `ccadmin` and the clearance
group `SCI_OPENSTACK_EU-DE-1_CCADMIN-DOMAIN_USER`, used for eu-de-1 ccadmin access.
It resolves the group and membership through Keystone's configured identity
backend, including `cc_ldap`, using its existing AD connection.

The check returns true for:

- Recipients whose identity domain is not `ccadmin`.
- Users in `ccadmin` who belong to the clearance group.
- The clearance group itself, or another nonempty `ccadmin` group whose currently
  resolved members all belong to the clearance group.

Other recipients in `ccadmin` return false. Missing recipient metadata, a missing
clearance group, and backend lookup failures also return false. Other LDAP login
exceptions, such as technical-user groups, do not establish clearance.

The restriction follows the **recipient's identity domain**, regardless of the
caller's domain or the scope receiving the role assignment. A cleared recipient
still needs the usual grant authorization to succeed.

#### Policy wiring

The narrow role allowlist belongs in the deployment's policy. For example:

```yaml
ccadmin_narrow_roles: >-
  'registry_viewer':%(target.role.name)s or
  'registry_pusher':%(target.role.name)s or
  'objectstore_viewer':%(target.role.name)s or
  'objectstore_admin':%(target.role.name)s
ccadmin_recipient_ok: "rule:ccadmin_narrow_roles or cc_clearance:recipient"
```

Choose the actual allowed role/scope combinations for the deployment. Wrap the
existing expression for each grant-creation policy and append the new condition:

```text
(<existing authorization expression>) and rule:ccadmin_recipient_ok
```

Apply this to `identity:create_grant`, `identity:create_system_grant_for_user`, and
`identity:create_system_grant_for_group`. The existing caller authorization and
other grant restrictions must remain inside the parenthesized expression so that
even a cloud administrator must satisfy the recipient restriction. Ordinary and
inherited project/domain grant endpoints share `identity:create_grant`.

Installing the package alone does not activate the restriction. Deploy the policy
in the intended region and restart workers after installing the updated package.

This is a grant-time check. Existing assignments, later AD membership changes,
role implications and token revocation remain under separate operational
controls. Group membership is evaluated as resolved by the identity backend at
the time of the grant, not as a guarantee about future members. Internal manager
calls, including bootstrap, do not pass through API policy enforcement.


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

Introduces a concept of user punishment for requests that caused an error.

The cost of each error type (identified by a response status >= 400) can be configured.

A user starts with a configurable initial credit, that is refilled by a configurable amount in a configurable interval.

Once a user has consumed all his credit and causes an error, his requests are blocked (rejected with a 429) until his credit has been refilled.

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

The middleware is enabled by adding it to paste.ini:

    [filter:lifesaver]
    use = egg:keystone-extensions#lifesaver


    [pipeline:api_v3]
    # The last item in this pipeline must be service_v3 or an equivalent
    # application. It cannot be a filter.
    pipeline = healthcheck cors sizelimit http_proxy_to_wsgi osprofiler url_normalize request_id lifesaver build_auth_context token_auth json_body ec2_extension_v3 s3_extension service_v3

or via flask [ugly hardcoding](https://github.com/sapcc/keystone/blob/0cedc509def82d28737f9f7dfd105ec528060f18/keystone/server/flask/core.py#L76-L80)
