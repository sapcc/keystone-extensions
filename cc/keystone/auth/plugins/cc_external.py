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

from oslo_config import cfg
from oslo_log import log

import six

from keystone.auth.plugins import base
from keystone.auth.plugins import core
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

    def authenticate(self, request, auth_info):
        """Use HTTP_X_USER_NAME to look up the user in the identity backend.
        """
        response_data = {}

        try:
            # trusted-key header configured?
            if CONF.cc_external.trusted_key_value:
                # check it
                secret = request.environ[CONF.cc_external.trusted_key_header]
                if secret != CONF.cc_external.trusted_key_value:
                    raise KeyError
        except KeyError:
            LOG.error("Authentication failed. Invalid trusted secret from: %s" % request.environ['REMOTE_ADDR'])
            msg = _('Authentication requested from a untrusted source')
            raise exception.Unauthorized(msg)

        try:
            REMOTE_USER = request.environ[CONF.cc_external.user_name_header]
        except KeyError:
            LOG.error(
                "Authentication failed. Missing username from: %s" % request.environ['REMOTE_ADDR'])
            msg = _('Invalid username')
            raise exception.Unauthorized(msg)
        try:
            user_ref = self._authenticate(REMOTE_USER, request)
            user_info = core.BaseUserInfo.create(user_ref, METHOD_NAME)
            response_data['user_id'] = user_info.user_id

            return base.AuthHandlerResponse(status=True, response_body=None,
                                            response_data=response_data)

        except Exception as e:
            LOG.info(
                "Authentication failed. Invalid username %s from %s: %s" % (REMOTE_USER, request.environ['REMOTE_ADDR'], e))
            msg = _('Authentication failed: %s' % e)
            raise exception.Unauthorized(msg)

    @abc.abstractmethod
    def _authenticate(self, remote_user, context):
        """Look up the user in the identity backend.

        Return user_ref
        """
        pass


class Domain(Base):
    def __init__(self):
        group = cfg.OptGroup(name='cc_external', title='Converged Cloud external auth header options')
        CONF.register_group(group)
        CONF.register_opt(
            cfg.StrOpt('user_name_header', default='HTTP_X_USER_NAME', help='The request header for the username'),
            group=group)
        CONF.register_opt(
            cfg.StrOpt('user_domain_name_header', default='HTTP_X_USER_DOMAIN_NAME', help='The request header for the users domainname'),
            group=group)
        CONF.register_opt(
            cfg.StrOpt('trusted_key_header', default='HTTP_X_TRUSTED_KEY', help='The request header for the trusted key'),
            group=group)
        CONF.register_opt(
            cfg.StrOpt('trusted_key_value', help='The trusted key'),
            group=group)
        super(Base, self).__init__()

    def _authenticate(self, remote_user, request):
        """Use HTTP_X_USER_NAME to look up the user in the identity backend.

        The domain will be extracted from the HTTP_X_USER_DOMAIN_NAME environment variable
        """
        try:
            domain_name = request.environ[CONF.cc_external.user_domain_name_header]
            LOG.info("Authenticating %s @ %s.." % (remote_user, domain_name) )
        except KeyError:
            LOG.error(
                "Authentication failed. Missing domain name from: %s" % request.environ['REMOTE_ADDR'])
            raise exception.Unauthorized('Missing domain name')

        user_ref = {'user': {'name': remote_user, 'domain': {'name': domain_name}}}
        return user_ref