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

"""Radius-based One-time Passcode auth plugin

"""
import re

import radius

from oslo_config import cfg
from oslo_log import log

from keystone.auth.plugins import base
from keystone.auth import plugins
from keystone import exception
from keystone.i18n import _
import keystone.conf

METHOD_NAME = 'radius'

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

# CID users
UID_REGEX = r'^[C-D|I]\d+$'


class Radius(base.AuthMethodHandler):
    def __init__(self):
        group = cfg.OptGroup(name='cc_radius', title='Radius options')
        CONF.register_group(group)
        CONF.register_opt(cfg.StrOpt('host', default=None, help='Radius server'), group=group)
        CONF.register_opt(cfg.IntOpt('port', default=None, help='Radius port.'), group=group)
        CONF.register_opt(cfg.StrOpt('secret', default=None, secret=True, help='Radius shared secret.'), group=group)

    def authenticate(self, request, auth_payload):
        """Try to authenticate using SecurID ober Radius"""
        response_data = {}

        user_info = plugins.TOTPUserInfo.create(auth_payload, METHOD_NAME)
        auth_passcode = auth_payload.get('user').get('passcode')

        LOG.info("Authenticating %s's SecurID passcode" % user_info.user_ref['name'])

        if not re.match(UID_REGEX, user_info.user_ref['name']):
            # authentication failed because of invalid username
            raise exception.Unauthorized('SecurID/Radius authentication is only supported for CID users')

        if not CONF.cc_radius.host or not CONF.cc_radius.port or not CONF.cc_radius.secret:
            raise exception.Unauthorized('SecurID/Radius backend service configuration is missing')

        try:
            if not radius.authenticate(CONF.cc_radius.secret, user_info.user_ref['name'], auth_passcode,
                                       host=CONF.cc_radius.host, port=CONF.cc_radius.port):
                LOG.info("Authentication failed: SecurID token of '%s' invalid" % user_info.user_ref['name'])
                # authentication failed because of invalid username or passcode
                msg = _('Invalid username or passcode')
                raise exception.Unauthorized(msg)
        except exception.Unauthorized:
            raise
        except Exception as e:
            LOG.error("Authentication failed: SecurID verification of '%s' failed: %s" % (user_info.user_ref['name'], e))
            # authentication failed because of radius backend issue
            msg = _('SecurID authentication failed')
            raise exception.Unauthorized(msg)

        response_data['user_id'] = user_info.user_id

        return base.AuthHandlerResponse(status=True, response_body=None,
                                        response_data=response_data)
