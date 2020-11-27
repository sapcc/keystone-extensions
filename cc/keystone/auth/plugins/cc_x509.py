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
import flask

from oslo_config import cfg
from oslo_log import log

import six

from keystone.auth.plugins import base
from keystone.auth import plugins
from keystone import exception
from keystone.i18n import _

from OpenSSL import crypto

from urllib.parse import unquote_to_bytes

CONF = cfg.CONF
LOG = log.getLogger(__name__)

METHOD_NAME = 'external'


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
            certificate = flask.request.environ[CONF.cc_x509.certificate_header]
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, unquote_to_bytes(certificate))

            # is it stil valid?
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
                LOG.info("%s", crypto.dump_certificate(crypto.FILETYPE_TEXT, cert))
            raise exception.Unauthorized("Authentication failed. No trusted certificate provided: %s" % e)

        try:
            user_ref = self._authenticate(username)
            user_info = plugins.BaseUserInfo.create(user_ref, METHOD_NAME)
            response_data['user_id'] = user_info.user_id
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
