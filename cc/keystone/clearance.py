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

"""Protect admin domains and check AD clearance before assigning roles."""

from oslo_log import log
from oslo_policy import policy

from keystone.common import provider_api
from keystone import exception


PROVIDERS = provider_api.ProviderAPIs
LOG = log.getLogger(__name__)

# Fixed admin domains and AD group for this first version.
ADMIN_DOMAINS = ('Default', 'ccadmin')
RESTRICTED_DOMAIN = 'ccadmin'
CLEARANCE_GROUP = 'SCI_OPENSTACK_EU-DE-1_CCADMIN-DOMAIN_USER'


class ClearanceCheck(policy.Check):
    """Check who can get a role and where the role can be assigned."""

    def __call__(self, target, creds, enforcer, current_rule=None):
        if self.match not in ('recipient', 'domain_boundary'):
            return False

        try:
            if self.match == 'domain_boundary':
                return self._domain_boundary(target, current_rule)
            return self._unrestricted_recipient(target)
        except exception.NotFound:
            # A domain or group is missing, or the user is not a member.
            return False
        except Exception as error:
            # Log only the error type; messages may contain passwords.
            LOG.error('Could not check role assignment (%s)',
                      type(error).__name__)
            return False

    def _recipient_domain(self, target):
        # Keystone supplies the user or group details in these policy fields.
        user_id = target.get('target.user.id')
        group_id = target.get('target.group.id')
        if bool(user_id) == bool(group_id):
            return None

        recipient_type = 'user' if user_id else 'group'
        domain_id = target.get('target.%s.domain_id' % recipient_type)
        if not domain_id:
            return None
        return PROVIDERS.resource_api.get_domain(domain_id)

    def _domain_boundary(self, target, current_rule):
        recipient_domain = self._recipient_domain(target)
        if not recipient_domain:
            return False

        # System grants can give access across every domain.
        if current_rule in (
            'identity:create_system_grant_for_user',
            'identity:create_system_grant_for_group',
        ):
            return recipient_domain['name'] in ADMIN_DOMAINS

        project_id = target.get('target.project.id')
        domain_id = target.get('target.domain.id')
        if bool(project_id) == bool(domain_id):
            return False
        if project_id:
            domain_id = target.get('target.project.domain_id')
        if not domain_id:
            return False

        target_domain = PROVIDERS.resource_api.get_domain(domain_id)
        if target_domain['name'] not in ADMIN_DOMAINS:
            return True
        return recipient_domain['name'] in ADMIN_DOMAINS

    def _unrestricted_recipient(self, target):
        domain = self._recipient_domain(target)
        if not domain:
            return False
        if domain['name'] != RESTRICTED_DOMAIN:
            return True

        user_id = target.get('target.user.id')
        group_id = target.get('target.group.id')
        identity = PROVIDERS.identity_api
        clearance_group = identity.get_group_by_name(
            CLEARANCE_GROUP, domain['id'])
        clearance_group_id = clearance_group['id']

        if user_id:
            identity.check_user_in_group(user_id, clearance_group_id)
            return True

        if group_id == clearance_group_id:
            return True

        # Every member Keystone can find must be in the clearance group.
        # Later membership changes need separate checks.
        members = identity.list_users_in_group(group_id)
        if not members:
            return False
        cleared_ids = {
            user['id']
            for user in identity.list_users_in_group(clearance_group_id)
        }
        return all(user['id'] in cleared_ids for user in members)
