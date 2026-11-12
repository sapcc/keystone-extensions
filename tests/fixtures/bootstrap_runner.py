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

"""Run the real management entry point with a read-only LDAP test double."""

import sys
import types
from unittest import mock

from keystone.identity.backends import ldap
from keystone.identity import core


# Kubernetes is used by other management commands, not by bootstrap.
kubernetes = types.ModuleType('kubernetes')
kubernetes.client = kubernetes.config = None
sys.modules['kubernetes'] = kubernetes

from cc.keystone.cmd import manage  # noqa: E402


if __name__ == '__main__':
    driver = mock.Mock(spec=ldap.Identity)
    driver.is_sql = False
    driver.is_domain_aware.return_value = False
    driver.generates_uuids.return_value = False
    driver.get_group_by_name.side_effect = lambda name, domain_id: {
        'id': 'directory-local-' + name, 'name': name}
    with mock.patch.object(core.DomainConfigs, '_load_driver',
                           return_value=driver):
        manage.main()
