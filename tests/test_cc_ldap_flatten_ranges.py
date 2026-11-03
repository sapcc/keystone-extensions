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

import unittest

from cc.keystone.identity.backends import cc_ldap


class _FakeConnection:
    """Minimal LDAP connection returning Active Directory range chunks.

    ``responses`` maps a requested ranged attribute name (e.g.
    ``member;range=0-1499``) to the ``(returned_attribute_name, values)``
    tuple the server answers with. Active Directory signals the final
    chunk by setting the upper bound to ``*`` in the returned name.
    """

    def __init__(self, responses):
        self._responses = responses
        self.requested = []

    def search_s(self, dn, scope, attrlist=None):
        requested_attr = attrlist[0]
        self.requested.append(requested_attr)
        returned_attr, values = self._responses[requested_attr]
        return [(dn, {returned_attr: values})]


class _FakeConnectionContext:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self._conn

    def __exit__(self, *args):
        return False


def _make_group_api(conn):
    # Build the API object without running the heavy __init__ that would
    # require a full LDAP configuration; flatten_ranges only needs
    # get_connection().
    api = cc_ldap.GroupApi.__new__(cc_ldap.GroupApi)
    api.get_connection = lambda: _FakeConnectionContext(conn)
    return api


class TestFlattenRanges(unittest.TestCase):

    def test_consolidates_all_range_chunks(self):
        first = ['cn=u%d' % i for i in range(0, 1500)]
        second = ['cn=u%d' % i for i in range(1500, 3000)]
        third = ['cn=u%d' % i for i in range(3000, 3500)]
        responses = {
            'member;range=0-1499': ('member;range=0-1499', first),
            'member;range=1500-2999': ('member;range=1500-2999', second),
            'member;range=3000-4499': ('member;range=3000-*', third),
        }
        conn = _FakeConnection(responses)
        api = _make_group_api(conn)

        member = {'member;range=0-1499': list(first)}
        api.flatten_ranges('cn=group', member)

        self.assertEqual(first + second + third, member['member'])

    def test_single_open_ended_chunk(self):
        values = ['cn=u%d' % i for i in range(0, 200)]
        responses = {
            'member;range=0-1499': ('member;range=0-*', values),
        }
        conn = _FakeConnection(responses)
        api = _make_group_api(conn)

        member = {'member;range=0-1499': list(values)}
        api.flatten_ranges('cn=group', member)

        self.assertEqual(values, member['member'])

    def test_attribute_without_range_is_left_unchanged(self):
        conn = _FakeConnection({})
        api = _make_group_api(conn)

        member = {'member': ['cn=u1', 'cn=u2']}
        api.flatten_ranges('cn=group', member)

        self.assertEqual(['cn=u1', 'cn=u2'], member['member'])
        self.assertEqual([], conn.requested)


if __name__ == '__main__':
    unittest.main()
