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

"""Keystone Header based Authentication Plugin"""

import abc
import flask

from oslo_config import cfg
from oslo_log import log

import six

from keystone.auth.plugins import base
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs
LOG = log.getLogger(__name__)

METHOD_NAME = 'external'


@six.add_metaclass(abc.ABCMeta)
class Base(base.AuthMethodHandler):

    def authenticate(self, auth_payload):
        """Use HTTP_X_USER_NAME to look up the user in the identity backend.
        """
        response_data = {}

        try:
            # trusted-key header configured?
            if CONF.cc_external.trusted_key_value:
                # check it
                secret = flask.request.environ[CONF.cc_external.trusted_key_header]
                if secret != CONF.cc_external.trusted_key_value:
                    raise KeyError
        except KeyError:
            LOG.error(
                "Authentication failed. Invalid trusted secret from: %s" % flask.request.environ.get('REMOTE_ADDR'))
            msg = _('Authentication requested from a untrusted source')
            raise exception.Unauthorized(msg)

        try:
            remote_user = flask.request.environ[CONF.cc_external.user_name_header]
            user_ref = self._authenticate(remote_user)
        except Exception:
            msg = _('Unable to lookup user %s') % flask.request.environ.get(CONF.cc_external.user_name_header)
            raise exception.Unauthorized(msg)

        response_data['user_id'] = user_ref['id']
        return base.AuthHandlerResponse(status=True, response_body=None,
                                        response_data=response_data)

    @abc.abstractmethod
    def _authenticate(self, remote_user):
        """Look up the user in the identity backend.

        Return user_ref
        """
        pass


class DefaultDomain(Base):
    def _authenticate(self, remote_user):
        """Use remote_user to look up the user in the identity backend."""
        return PROVIDERS.identity_api.get_user_by_name(remote_user, CONF.identity.default_domain_id)


class Domain(Base):
    def __init__(self):
        group = cfg.OptGroup(name='cc_external', title='Converged Cloud external auth header options')
        CONF.register_group(group)
        CONF.register_opt(
            cfg.StrOpt('user_name_header', default='HTTP_X_USER_NAME', help='The request header for the username'),
            group=group)
        CONF.register_opt(
            cfg.StrOpt('user_domain_name_header', default='HTTP_X_USER_DOMAIN_NAME',
                       help='The request header for the users domainname'),
            group=group)
        CONF.register_opt(
            cfg.StrOpt('trusted_key_header', default='HTTP_X_TRUSTED_KEY',
                       help='The request header for the trusted key'),
            group=group)
        CONF.register_opt(
            cfg.StrOpt('trusted_key_value', help='The trusted key'),
            group=group)
        super(Base, self).__init__()

    def _authenticate(self, remote_user):
        """Use HTTP_X_USER_NAME to look up the user in the identity backend.

        The domain will be extracted from the HTTP_X_USER_DOMAIN_NAME environment variable
        """
        try:
            domain_name = flask.request.environ[CONF.cc_external.user_domain_name_header]
            LOG.info("Authenticating %s @ %s.." % (remote_user, domain_name))
            if domain_name:
                ref = PROVIDERS.resource_api.get_domain_by_name(domain_name)
                domain_id = ref['id']
            else:
                domain_id = CONF.identity.default_domain_id

            return PROVIDERS.identity_api.get_user_by_name(remote_user, domain_id)
        except KeyError:
            LOG.error(
                "Authentication failed. Missing domain name from: %s" % flask.request.environ.get('REMOTE_ADDR'))
            raise exception.Unauthorized('Missing domain name')
