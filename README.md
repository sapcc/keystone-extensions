# Converged Cloud Keystone Extensions

This package adds a custom identity driver, authentication plugins, policy checks,
lifesaver middleware, and management commands to Keystone.

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


### The cc_clearance policy checks

The plugin provides two checks. Use both in Keystone policy.

#### Keep admin access in admin domains

`cc_clearance:domain_boundary` checks where a role is being assigned:

- On a project in `Default` or `ccadmin`, the user or group getting the role must
  belong to either `Default` or `ccadmin`.
- The same rule applies to roles assigned on those domains, including inherited
  roles, and to system-wide roles.
- On projects and domains elsewhere, this check passes. The usual Keystone
  permission checks still apply.

For now, `Default` and `ccadmin` are fixed in the code as the admin domains. These
names match the domains listed in eu-de-1's `adminDomainIds` setting. The plugin
does not read that setting yet. Service accounts in `Default` can still receive
roles in `ccadmin`, and recipients in `ccadmin` can receive roles in `Default`.
Users from other domains cannot receive even `member` on an admin-domain project.

The domain boundary protects grants in both admin domains. The clearance check
below applies only to recipients in `ccadmin`.

#### Limit roles for uncleared ccadmin users

`cc_clearance:recipient` checks who is getting a role:

- Users in the AD clearance group can receive any role allowed by the usual
  Keystone rules.
- Other users in `ccadmin` can receive only the roles listed in policy.
- Users and groups outside `ccadmin` pass the clearance check. They must still
  pass the domain check above.

For the clearance check, the domain name `ccadmin` and the AD group name
`SCI_OPENSTACK_EU-DE-1_CCADMIN-DOMAIN_USER` are fixed in the code. This is the group
used for eu-de-1 ccadmin access. The check uses Keystone's existing AD connection
to look up the group and its members.

For groups in `ccadmin`, only the clearance group itself passes. Other groups
are limited to the small role list, even if all their current members are
cleared. A grant belongs to the group and also applies to members added later.

If user or group details are missing, or a lookup fails, the check returns false.
Being in a technical-user login group does not count as clearance.

The clearance check uses the domain where the user or group belongs. For example,
a role given to a `ccadmin` user is checked even if the project is in another
domain. The person giving the role must still have permission to do so.

#### Enable the checks

Install the updated package, add the rules below to the chosen region's policy
file, and restart the Keystone workers. Keystone loads the plugin automatically;
no Keystone code changes are needed.

Choose the roles that uncleared users and other `ccadmin` groups may receive.
For example:

```yaml
ccadmin_narrow_roles: >-
  'registry_viewer':%(target.role.name)s or
  'registry_pusher':%(target.role.name)s or
  'objectstore_viewer':%(target.role.name)s or
  'objectstore_admin':%(target.role.name)s
ccadmin_recipient_ok: "rule:ccadmin_narrow_roles or cc_clearance:recipient"
```

Decide which roles to allow and where they may be assigned. Add both checks to
the existing rules for assigning roles:

```text
(<current rule>)
and cc_clearance:domain_boundary
and rule:ccadmin_recipient_ok
```

Do this for:

- `identity:create_grant`
- `identity:create_system_grant_for_user`
- `identity:create_system_grant_for_group`

Keep the whole current rule inside the parentheses, including the existing
`adminDomainIds` and role-blocklist checks. Both new checks must pass even when
a cloud administrator gives someone a role. Keep `cc_clearance:domain_boundary`
outside the allowed-role condition so that an allowed role cannot bypass it.
`identity:create_grant` covers both ordinary and inherited project/domain roles.

#### What this checks

These checks run when a role is assigned through the Keystone API:

- The clearance check uses AD membership when a user receives a role.
  Later membership changes need separate monitoring.
- They do not remove old assignments, change implied roles or revoke tokens.
- Bootstrap and other direct calls to Keystone's internal managers skip API
  policy checks.


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
