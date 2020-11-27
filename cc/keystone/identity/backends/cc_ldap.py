# Copyright 2018 SAP SE
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

# -*- coding: utf-8 -*-

"""Converged Cloud Identity LDAP backend driver for Keystone """
import re
import datetime
import ldap

from oslo_config import cfg
from oslo_log import log

from keystone import exception
from keystone.identity.backends import ldap as ldap_backend
from keystone.identity.backends import base
from keystone.identity.backends.ldap import common as common_ldap
from keystone.identity.backends.ldap import core as core_ldap
from keystone.identity.backends.ldap import models
from keystone.i18n import _

CONF = cfg.CONF
LOG = log.getLogger(__name__)

STATUS_ACTIVE = u'active'
STATUS_INACTIVE = u'inactive'
CAM_STATUS_ACTIVE = u'X'
UID_REGEX = r'^[C-D|I]\d+$'
# temporary technical users that CAM loves to fool around with
T_REGEX = r'^T([0-9A-Fa-f]{16})'


class CCUser(models.User):
    """
    Extended user class with SAP specific user (internal) attributes
    """
    optional_keys = models.User.optional_keys + \
                    ('sapObjectStatus', 'ccObjectStatus', 'camObjectStatus', 'password_expires_at', 'password_failures',
                     'userAccountControl')


class Identity(ldap_backend.Identity):
    def __init__(self, conf=None):
        self.conf = conf
        if self.conf is None:
            self.conf = CONF

        super(Identity, self).__init__(self.conf)
        self.user = UserApi(self.conf)
        self.group = GroupApi(self.conf)

    def change_password(self, user_id, new_password):
        self.update_user(user_id, {'password': new_password})

    def update_user(self, user_id, user):
        # only allow password or status changes
        allowed = ['password', 'enabled', 'login']
        for k in user:
            if k not in allowed:
                self._disallow_write()

        old_obj = self.user.get(user_id)
        if 'name' in user and old_obj.get('name') != user['name']:
            raise exception.Conflict(_('Cannot change user name'))

        if 'password' in user:
            # force LDAP replace
            old_obj['password'] = 'fake'
            LOG.info("User password update %s" % user_id)

        # special CC sauce to allow onboarding of new provisioned CAM users with no password and userAccountControl 514
        if 'login' in user:
            user.pop('login')
            if 'ccObjectStatus' not in old_obj:
                # this indicates that it is indeed a freshly provisioned CAM user: enable the user
                user['enabled'] = True

        if 'enabled' in user:
            if user['enabled']:
                if 'sapObjectStatus' in old_obj and \
                        old_obj['sapObjectStatus'] != STATUS_ACTIVE:
                    raise exception.Conflict(_('User is inactive.'))
                else:
                    user['ccObjectStatus'] = STATUS_ACTIVE
            else:
                user['ccObjectStatus'] = STATUS_INACTIVE
            if self.user.enabled_mask:
                self.user.mask_enabled_attribute(user)
            elif self.user.enabled_invert and not self.user.enabled_emulation:
                # We need to invert the enabled value for the old model object
                # to prevent the LDAP update code from thinking that the enabled
                # values are already equal.
                user['enabled'] = not user['enabled']
                old_obj['enabled'] = not old_obj['enabled']

        if 'camObjectStatus' in user and old_obj.get('camObjectStatus') != \
                user['camObjectStatus']:
            raise exception.ForbiddenNotSecurity(
                _('user.camObjectStatus is a read-only attribute'))
        if 'sapObjectStatus' in user and old_obj.get('sapObjectStatus') != \
                user['sapObjectStatus']:
            raise exception.ForbiddenNotSecurity(
                _('user.sapObjectStatus is a read-only attribute'))

        try:
            self.user.update(user_id, user, old_obj)
        except ldap.UNWILLING_TO_PERFORM as e:
            # If the exceptions's 'info' field begins with:
            #  00000056 - Current passwords do not match
            #  0000052D - New password violates length/complexity/history
            msg = e[0]['desc']
            LOG.error("User update %s failed: %s" % (user_id, msg))

            if e[0]['info'].startswith('0000052D'):
                msg = '"Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain." '
                raise exception.PasswordRequirementsValidationError(msg)
            else:
                raise e
        return self.user.get_filtered(user_id)


class UserApi(ldap_backend.UserApi):
    def __init__(self, conf=None):
        self.conf = conf
        if self.conf is None:
            self.conf = CONF

        super(UserApi, self).__init__(self.conf)
        # inject the extended CC user model
        self.model = CCUser
        self.attribute_mapping['sapObectStatus'] = 'sapObjectStatus'
        self.attribute_mapping['ccObjectStatus'] = 'ccObjectStatus'
        self.attribute_mapping['camObjectStatus'] = 'camObjectStatus'
        self.attribute_mapping['password_expires_at'] = 'pwdLastSet'
        self.attribute_mapping['password_failures'] = 'badPwdCount'

    def filter_attributes(self, user):
        # make sure inactive users are disabled
        if 'sapObjectStatus' in user:
            if user['sapObjectStatus'] != STATUS_ACTIVE:
                user['enabled'] = False
        if 'camObjectStatus' in user:
            if user['camObjectStatus'] != CAM_STATUS_ACTIVE:
                user['enabled'] = False
        if 'ccObjectStatus' in user:
            if user['ccObjectStatus'] != STATUS_ACTIVE:
                user['enabled'] = False
            # keep CAM from messing with temporary T-users
            elif re.match(T_REGEX, user['name']):
                user['enabled'] = True
        else:
            # special case for fresh priovisioned CAM users: we transiently enable them to allow a initial login
            # the following pasword update will take care of setting the ccObjectStatus
            if not user['enabled'] and user['camObjectStatus'] == CAM_STATUS_ACTIVE:
                user['enabled'] = True

        user.pop('sAMAccountName', None)
        user.pop('sapObjectStatus', None)
        user.pop('ccObjectStatus', None)
        user.pop('camObjectStatus', None)

        # evaluate password_expires_at
        if 'password_expires_at' in user:
            if user['password_expires_at'] == '0' or user['password_expires_at'] == '9223372036854775807':
                user['password_expires_at'] = None
            else:
                # convert pwdLastSet to unix epoch
                ts = (int(user['password_expires_at']) / 10000000) - 11644473600
                # TODO: this is over simplified and actually potentially dynamic (AD policy based)
                # add max 180 days AD policy based password age
                ts += 15552000
                user['password_expires_at'] = datetime.datetime.fromtimestamp(ts)

        if 'userAccountControl' in user:
            do_not_expire = int(user['userAccountControl']) & 0x10000  # AD PASSWORD_NEVER_EXPIRES bit
            if do_not_expire:
                user['password_expires_at'] = None
            user.pop('userAccountControl', None)

        if 'password_failures' in user:
            if user['password_failures'] == '0':
                user.pop('password_failures', None)

        return base.filter_user(common_ldap.filter_entity(user))


class GroupApi(ldap_backend.GroupApi):
    def __init__(self, conf=None):
        self.conf = conf
        if self.conf is None:
            self.conf = CONF

        super(GroupApi, self).__init__(self.conf)

    def list_group_users(self, group_id):
        """Return a list of user dns which are members of a group."""
        group_ref = self.get(group_id)
        group_dn = group_ref['dn']

        try:
            if self.group_ad_nesting:
                # NOTE(ayoung): LDAP_SCOPE is used here instead of hard-
                # coding to SCOPE_SUBTREE to get through the unit tests.
                # However, it is also probably more correct.
                attrs = self._ldap_get_list(
                    self.tree_dn, self.LDAP_SCOPE,
                    query_params={
                        "member:%s:" % core_ldap.LDAP_MATCHING_RULE_IN_CHAIN:
                            group_dn},
                    attrlist=[self.member_attribute])
            else:
                attrs = self._ldap_get_list(group_dn, ldap.SCOPE_BASE,
                                            attrlist=[self.member_attribute])

        except ldap.NO_SUCH_OBJECT:
            raise self.NotFound(group_id=group_id)

        users = []
        for dn, member in attrs:
            # CCloud: we need to support AD group member range retrieval for large groups (>1500 members)
            self.flatten_ranges(dn, member)

            user_dns = member.get(self.member_attribute, [])
            for user_dn in user_dns:
                users.append(user_dn)
        return users

    # Takes care of flattening active directory group member ranged query responses
    # https://msdn.microsoft.com/en-us/library/Aa367017
    def flatten_ranges(self, dn, member):
        for attrname in member:
            if ';range=' in attrname:
                actual_attrname, range_stmt = attrname.split(';')
                bound_lower, bound_upper = [
                    int(x) for x in range_stmt.split('=')[1].split('-')
                ]

                step = bound_upper - bound_lower + 1
                while True:
                    attr_next = '%s;range=%d-%d' % (
                        actual_attrname, bound_lower, bound_upper
                    )

                    with self.get_connection() as conn:
                        dn, attrs = conn.search_s(
                            dn, ldap.SCOPE_BASE, attrlist=[attr_next])[0]

                    assert len(attrs) == 1

                    ret_attrname = attrs.keys()[0]

                    member[actual_attrname].extend(attrs[ret_attrname])
                    if ret_attrname.endswith('-*'):
                        break

                    bound_lower = bound_upper + 1
                    bound_upper += step
