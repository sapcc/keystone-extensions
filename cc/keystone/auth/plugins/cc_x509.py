# Copyright 2017 SAP SE
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

"""Keystone x509 based Authentication Plugin"""

import abc
import base64
import binascii
import flask
import re

from oslo_config import cfg
from oslo_log import log

import six

from keystone.auth.plugins import base
from keystone.auth import plugins
from keystone.common import provider_api
from keystone import exception
from keystone import notifications
from keystone.i18n import _

from OpenSSL import crypto

from urllib.parse import unquote_to_bytes

PROVIDERS = provider_api.ProviderAPIs

CONF = cfg.CONF
LOG = log.getLogger(__name__)

METHOD_NAME = 'external'


def _ensure_pem(cert_text):
    """
    Ensure the provided certificate text is a PEM formatted block.
    Case 1: certificate already has PEM labels, nothing needs to be done.
    Case 2: certificate doesn't have PEM labels and is coming from Akamai.
    """
    if not cert_text:
        return cert_text

    if isinstance(cert_text, bytes):
        cert_text = cert_text.decode('utf-8')  # cert might be bytes

    if ('BEGIN%20CERTIFICATE' in cert_text and 'END%20CERTIFICATE' in cert_text):
        # Case 1 - already PEM formatted, but not unquoted
        return cert_text

    # Case 2 - add new line breaks every 64 chars to make a PEM format
    cert = re.sub("(.{64})", "\\1\n", cert_text, 0, re.DOTALL)

    # Case 2 - add PEM labels around the result
    cert = '-----BEGIN CERTIFICATE-----\n%s\n%s' % (cert, '-----END CERTIFICATE-----')

    return cert


@six.add_metaclass(abc.ABCMeta)
class Base(base.AuthMethodHandler):

    def authenticate(self, auth_info):
        """Use HTTP_SSL_CLIENT_CERT to look up the user in the identity backend.
        """
        response_data = {}
        cert = ''

        try:
            # client certificate validated?
            verification = flask.request.environ[CONF.cc_x509.certificate_verify_header]

            if verification != 'SUCCESS':
                raise Exception("Certificate has not been validated")

            # grab the certificate
            cert_header = flask.request.environ[CONF.cc_x509.certificate_header]

            # the certificate will be Base64 encoded when coming from Akamai:
            try:
                certificate = base64.b64decode(cert_header, validate=True)
            except binascii.Error:
                # if not base64 encoded, use as is:
                certificate = cert_header

            # ensure PEM markers are present and certificate formatted correctly
            certificate = _ensure_pem(certificate)

            cert = crypto.load_certificate(crypto.FILETYPE_PEM, unquote_to_bytes(certificate))

            # is it still valid?
            if cert.has_expired():
                raise Exception("certificate has expired")

            # check the issuer
            items = []
            x509name = cert.get_issuer()
            for item in reversed(x509name.get_components()):
                items.append('%s=%s' % (item[0].decode("utf-8"), item[1].decode("utf-8")))
            issuer = ",".join(items)

            if issuer not in CONF.cc_x509.trusted_issuer:
                raise Exception("certificate issuer %s is not configured as trusted issuer (we trust %s)" % (issuer, CONF.cc_x509.trusted_issuer))

            # and the subject (username)
            username = cert.get_subject().CN
        except Exception as e:
            LOG.info("Invalid certificate from %s: %s" % (flask.request.environ.get('REMOTE_ADDR'), e))
            if CONF.debug:
                try:
                    LOG.info("%s", crypto.dump_certificate(crypto.FILETYPE_TEXT, cert))
                except AttributeError:
                    # there is a bug somewhere that prevents dumping the
                    # cert info; since this is just a log message, it
                    # should not block us
                    LOG.info("Could not decode cert: \"%s\"", cert)
            raise exception.Unauthorized("Authentication failed. No trusted certificate provided: %s" % e)

        try:
            user_ref = self._authenticate(username)
            user_info = plugins.BaseUserInfo.create(user_ref, METHOD_NAME)
            response_data['user_id'] = user_info.user_id
            # at this point the user is considered to be authenticated, mark
            # the user as active
            ref = PROVIDERS.identity_api._shadow_nonlocal_user(user_info.user_ref)
            PROVIDERS.shadow_users_api.set_last_active_at(ref['id'])
            # send a notification. The notification wrapper expects that
            # there is a method that accepts user_id as the first argument,
            # and that method actually authenticates a user. Out mechanism
            # verifies authentication differently. So lets provide a simple
            # wrapper just to please the interface.
            # TODO: move the actual authn and certificate checks to this
            # method.
            self.authenticate_by_id(ref['id'])

            return base.AuthHandlerResponse(status=True, response_body=None,
                                            response_data=response_data)
        except Exception as e:
            LOG.info(
                "Authentication failed. Invalid username %s from %s: %s" % (username, flask.request.environ.get('REMOTE_ADDR'), e))
            msg = _('Authentication failed: %s' % e)
            raise exception.Unauthorized(msg)

    @abc.abstractmethod
    def _authenticate(self, remote_user):
        """Look up the user in the identity backend.

        Return user_ref
        """
        pass

    @notifications.emit_event('authenticate')
    def authenticate_by_id(self, user_id):
        pass


class Certificate(Base):
    def __init__(self):
        group = cfg.OptGroup(name='cc_x509', title='Converged Cloud certificate auth options')
        CONF.register_group(group)
        CONF.register_opt(
            cfg.StrOpt('certificate_verify_header', default='HTTP_SSL_CLIENT_VERIFY', help='The request header for the client verification outcome'),
            group=group)
        CONF.register_opt(
            cfg.StrOpt('certificate_header', default='HTTP_SSL_CLIENT_CERT', help='The request header for the x509 certificate'),
            group=group)
        CONF.register_opt(
            cfg.MultiStrOpt('trusted_issuer', default=[], help='Trusted issuer (multiple arguments supported)'),
            group=group)
        CONF.register_opt(
            cfg.StrOpt('user_domain_name_header', default='HTTP_X_USER_DOMAIN_NAME', help='The request header for the users domainname'),
            group=group)
        CONF.register_opt(
            cfg.StrOpt('user_domain_id_header', default='HTTP_X_USER_DOMAIN_ID', help='The request header for the users domain-id'),
            group=group)
        super(Base, self).__init__()

    def _authenticate(self, username):
        """
        The user domain will be extracted from the HTTP_X_USER_DOMAIN_ID or HTTP_X_USER_DOMAIN_NAME environment variable
        """
        domain_id = None
        domain_name = None
        try:
            domain_id = flask.request.environ[CONF.cc_x509.user_domain_id_header]
        except KeyError:
            try:
                domain_name = flask.request.environ[CONF.cc_x509.user_domain_name_header]
            except KeyError:
                LOG.error("Authentication failed. Missing domain header from: %s" % flask.request.environ.get('REMOTE_ADDR'))
                raise exception.Unauthorized('Missing domain header')

        LOG.info("Authenticating %s@%s.." % (username, domain_name))
        user_ref = {'user': {'name': username, 'domain': {}}}
        if domain_name:
            user_ref['user']['domain'] = {'name': domain_name}
        if domain_id:
            user_ref['user']['domain'] = {'id': domain_id}
        return user_ref
