# Copyright 2026 SAP SE
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

"""Grant-time eligibility for roles outside the ccadmin narrow allowlist."""

from oslo_log import log
from oslo_policy import policy

from keystone.common import provider_api
from keystone import exception


PROVIDERS = provider_api.ProviderAPIs
LOG = log.getLogger(__name__)

# Prototype defaults: resolve names through Keystone's configured backends.
RESTRICTED_DOMAIN = 'ccadmin'
CLEARANCE_GROUP = 'SCI_OPENSTACK_EU-DE-1_CCADMIN-DOMAIN_USER'


class ClearanceCheck(policy.Check):
    """Implement ``cc_clearance:recipient`` using the grant recipient."""

    def __call__(self, target, creds, enforcer, current_rule=None):
        if self.match != 'recipient':
            return False

        try:
            return self._unrestricted_recipient(target)
        except exception.NotFound:
            # Includes a missing clearance group or absent user membership.
            return False
        except Exception as error:
            # Backend exception text can contain LDAP credentials or SQL data.
            LOG.error('Unable to check recipient clearance (%s)',
                      type(error).__name__)
            return False

    def _unrestricted_recipient(self, target):
        # These fields are populated and flattened by Keystone's grant APIs.
        user_id = target.get('target.user.id')
        group_id = target.get('target.group.id')
        if bool(user_id) == bool(group_id):
            return False

        recipient_type = 'user' if user_id else 'group'
        domain_id = target.get('target.%s.domain_id' % recipient_type)
        if not domain_id:
            return False

        domain = PROVIDERS.resource_api.get_domain(domain_id)
        if domain['name'] != RESTRICTED_DOMAIN:
            return True

        identity = PROVIDERS.identity_api
        clearance_group = identity.get_group_by_name(CLEARANCE_GROUP, domain_id)
        clearance_group_id = clearance_group['id']

        if user_id:
            identity.check_user_in_group(user_id, clearance_group_id)
            return True

        if group_id == clearance_group_id:
            return True

        # Group grants are eligible only when all currently resolved members
        # are cleared. Membership changes after the grant need separate control.
        members = identity.list_users_in_group(group_id)
        if not members:
            return False
        cleared_ids = {
            user['id']
            for user in identity.list_users_in_group(clearance_group_id)
        }
        return all(user['id'] in cleared_ids for user in members)
