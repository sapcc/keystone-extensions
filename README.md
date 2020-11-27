# Converged Cloud Keystone Extensions

Provides a custom identity driver, auth plugins, lifesaver middleware and keystone-manage-extension cli for keystone.

The identity driver supports:

- usage of Microsoft Active Directory as identitiy provider
- optional authentication fallback against a outlook exchange webservice
- optional outlook exchange webservice password mirroring on AD auth failure
- merging of several user account status flags (IDM/HR, CAM) into one
 keystone user.enabled attribute

The keystone-manage-extension cli provides

- a extended bootstrap command that takes care of giving the bootstrap user domain admon permissions
- a repair_assignments command to do a emergency role assignment cleanup after AD objects have been deleted that still have references to them

The auth plugins provide:

 - Radius / SecurID authentication
 - Password authentication with optional password validation against EWS and mirroring the externaly validated password to LDAP

The lifesaver middleware protects against abusive requests and rejects requests from users that have depleted their credit.

## Installation

Install the python package into the keystone (virtual) environment

    pip install git+https://github.wdf.sap.corp/monsoon/keystone-extensions.git


### Identity Driver

Enable keystone's [domain specific drivers](http://docs.openstack.org/developer/keystone/configuration.html#domain-specific-drivers)
and configure one or more domains to use the **cc_ldap** driver (instead of the usual sql or ldap).

The driver extends the standard keystone LDAP driver, so all [configuration
options of the LDAP driver](http://docs.openstack.org/developer/keystone/configuration.html#configuring-the-ldap-identity-provider) also apply to the CC_AD driver.


### The cc_password, cc_radius and cc_x509 auth plugins

The Converged Cloud authentication specific implementations are contained in keystone authentication plugins.

To replace the default keystone password-, external- and totp auth plugins with the CCloud versions, you need to override the plugin implementation in keystone.conf.

To enable the plugins, specify in keystone.conf:

    [auth]
    password = cc_password
    totp = cc_radius
    external = cc_x509

    methods = password,token,totp

The cc_password plugin offers the SAP specific password mirroring logic from GLOBAL AD, via a password verification hack against the Outlook External Web Service (EWS).
If the password validation against AD fails, it will try to verify the same password against EWS.
If that succeeds, it is assumed that a GLOBAL password update has taken place and the CCloud AD password of the user is updated with the new password.

The plugin offers the following configuration settings:

    [cc_password]
    url = <your outlook exchange external webservice url> (default is https://autodiscover.sap.com/autodiscover/autodiscover.xml)
    secure = <a boolean that indicates if the certificate of above URL should be verified>


To use the SecurID plugin, the Radius server details need to be configures in keystone.conf as well:

    [cc_radius]
    host = <your radius host>
    port = <the portnumber of the radius service on the host>    
    secret = <the shared secret>

Single signon support for Converged Cloud keystone consumers via the SAP SSO certificate is supported by the cc_x509 authentication plugin.
It supports authentication by evaluating the x509 client certificate headers (HTTP_SSL_CLIENT_VERIFY and HTTP_SSL_CLIENT_CERT)in a request and validating its content.
The request should also contain an additional HTTP_X_USER_DOMAIN_ID or HTTP_X_USER_DOMAIN_ID header to indicate what openstack domain should be used for the user validation.    
To use the cc_x509 plugin, it needs to be configured in keystone.conf:

    [cc_x509]
    user_domain_id_header = HTTP_X_USER_DOMAIN_ID
    user_domain_name_header = HTTP_X_USER_DOMAIN_NAME
    trusted_issuer = CN=SSO_CA,O=SAP-AG,C=DE
    trusted_issuer = CN=SSO CA G2,O=SAP SE,O=Walldorf,C=DE


### The lifesaver middleware

Introduces a concept of user punishment for requests that caused an error.

The cost of each error type (identified by a response status >= 400) can be configured.

A user starts with a configurable initial credit, that is refilled by a configurable amount in a configurable interval.

Once a user has consumed all his credit and causes an error, his requests are blocked (rejected with a 429) until his credit has been refiled.

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
