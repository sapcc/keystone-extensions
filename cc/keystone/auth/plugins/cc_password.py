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

import requests
import re

from requests.auth import to_native_string
from base64 import b64encode

from oslo_log import log
from oslo_config import cfg

from keystone.auth.plugins import base
from keystone.auth.plugins import core
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _

METHOD_NAME = 'password'
PROVIDERS = provider_api.ProviderAPIs

LOG = log.getLogger(__name__)
CONF = keystone.conf.CONF

# CID users
UID_REGEX = r'^[C-D|I]\d+$'


class Password(base.AuthMethodHandler):
    def __init__(self):
        super(Password, self).__init__()

        group = cfg.OptGroup(name='cc_password', title='Outlook Exchange Webservice options')
        CONF.register_group(group)
        CONF.register_opt(
            cfg.StrOpt('url', help='Password Verification Service URL'),
            group=group)
        CONF.register_opt(
            cfg.BoolOpt('secure', default=True, help='Verify Password Verification Service certificate'),
            group=group)

    def authenticate(self, auth_payload):
        response_data = {}

        try:
            domain = auth_payload['user'].get('domain', {})
            LOG.info("Authenticating %s@%s.." % (
                auth_payload['user'].get('name', auth_payload['user'].get('id', '<nil>')),
                domain.get('name', domain.get('id', '<nil>'))))
            user_info = core.UserAuthInfo.create(auth_payload, METHOD_NAME)
        except Exception as e:
            LOG.info("Authentication failed: %s" % e)
            raise

        try:
            # Try to authenticate against the identity backend.
            PROVIDERS.identity_api.authenticate(
                user_id=user_info.user_id,
                password=user_info.password)
        except AssertionError:
            try:
                # check if the user actually exists in domain, since the exception gives no clue about the root-cause
                self.identity_api.get_user(user_info.user_id)
            except Exception as e:
                LOG.info("Authentication failed: %s" % e)
                # authentication failed because of invalid username
                msg = _('Invalid username or password')
                raise exception.Unauthorized(msg)

            # if it is a CID user, check if the user has changed his GLOBAL password
            if re.match(UID_REGEX, user_info.user_ref['name']) \
                    and self._authenticate_ews(user_info.user_ref['name'], user_info.password):
                # and update the password in CCloud AD
                self._update_password(user_info)
            else:
                # authentication failed because of invalid username or password
                msg = _('Invalid username or password')
                raise exception.Unauthorized(msg)

        response_data['user_id'] = user_info.user_id
        return base.AuthHandlerResponse(status=True, response_body=None,
                                        response_data=response_data)

    @staticmethod
    def _authenticate_ews(username, password):
        """Authenticate a CID user against sap exchange webservice"""
        try:
            LOG.info("Authenticating %s with SAP Password Verification Service" % username)
            if not username or not password:
                msg = _('Invalid username or password')
                raise exception.Unauthorized(msg)

            # don't rely on requests to provide the auth header, since it fails
            # miserably with exotic characters in passwords (encoding != latin-1)
            basic_auth = 'Basic ' + to_native_string(b64encode(
                ('%s:%s' % (username, password)).encode('utf-8')).strip())

            response = requests.post(CONF.cc_password.url,
                                    headers={
                                        'Content-Type': 'application/json; charset=utf-8',
                                        'Authorization': basic_auth
                                    },
                                    verify=CONF.cc_password.secure)

            if response.status_code == 401:
                msg = _('Invalid username or password')
                raise exception.Unauthorized(msg)
            if response.status_code != 200:
                LOG.info(
                    "SAP Password Verification Service authentication of '%s' against '%s' was rejected: %s" % (
                        username, CONF.cc_password.url, response.reason))
                msg = _('Invalid username or password')
                raise exception.Unauthorized(msg)

            LOG.debug("Authenticated %s with Password Verification Service." % username)
            return True
        except exception.Unauthorized:
            raise
        except Exception as e:
            LOG.error(
                "SAP Password Verification Service authentication of '%s' against '%s' failed: %s" % (
                    username, CONF.cc_password.url, e))
            raise exception.Unauthorized('Callout to SAP Exchange for password verification failed.')

    @staticmethod
    def _update_password(userinfo):
        """Update a users password in LDAP"""
        try:
            LOG.info("Updating password of %s" % userinfo.user_ref['name'])
            # CC hack: add a fake login attribute, to allow initial on-boarding of freshly provisioned CAM users
            user = {"password": userinfo.password, "login": True}
            PROVIDERS.identity_api.update_user(user_id=userinfo.user_id, user_ref=user)
        except Exception as e:
            LOG.error("Password update of '%s' failed: %s" % (userinfo.user_ref['name'], e))
            # ignore for now, since the strict AD password policy might cause issues here and
            # the users password has been validated against Password Verification Service already
            # raise exception.Unauthorized(e)
