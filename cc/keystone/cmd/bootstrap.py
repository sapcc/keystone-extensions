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

"""Reconcile the Keystone bootstrap declarations through backend managers."""

import uuid

from oslo_log import log

from keystone.common import driver_hints
import keystone.conf
from keystone import exception
from keystone.server import backends

from cc.keystone.cmd.bootstrap_config import BootstrapError
from cc.keystone.cmd.bootstrap_config import load_config
from cc.keystone.cmd.bootstrap_config import ordered_regions
from cc.keystone.cmd.bootstrap_config import validate_config


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


def _changes(current, desired):
    # In particular, LDAP strings, booleans and integers must remain distinct.
    return {key: value for key, value in desired.items()
            if key not in current or type(current[key]) is not type(value)
            or current[key] != value}


def _create_with_id(create, attributes, resource_id=None):
    ref = dict(attributes, id=resource_id or uuid.uuid4().hex)
    return create(ref['id'], ref)


class Bootstrapper:
    def __init__(self, managers):
        self.resource_api = managers['resource_api']
        self.domain_config_api = managers['domain_config_api']
        self.identity_api = managers['identity_api']
        self.role_api = managers['role_api']
        self.assignment_api = managers['assignment_api']
        self.catalog_api = managers['catalog_api']
        self._cache = {}

    def apply(self, config):
        validate_config(config)
        if any('config' in domain for domain in config.get('domains', [])):
            if not (CONF.identity.domain_specific_drivers_enabled
                    and CONF.identity.domain_configurations_from_database):
                raise BootstrapError(
                    'Domain configuration requires [identity] '
                    'domain_specific_drivers_enabled and '
                    'domain_configurations_from_database')

        self._cache.clear()
        # Complete domain configuration before making any identity calls. The
        # identity manager then loads the right driver and public ID mappings.
        for section, reconcile in (
            ('domains', self._domain), ('roles', self._role),
            ('role_inferences', self._inference), ('regions', self._region),
            ('services', self._service), ('projects', self._project),
            ('users', self._user), ('groups', self._group),
            ('group_memberships', self._membership),
            ('role_assignments', self._assignment),
        ):
            items = config.get(section, [])
            if section == 'regions':
                items = ordered_regions(items)
            for index, item in enumerate(items):
                try:
                    reconcile(item)
                except BootstrapError:
                    raise
                except Exception as error:
                    # Backend exceptions can contain SQL parameters or LDAP
                    # credentials. Keep those out of the command's log output.
                    raise BootstrapError(
                        'Failed to reconcile %s[%s] (%s)' %
                        (section, index, type(error).__name__)) from error
        LOG.info('Keystone bootstrap completed')

    def _ensure(self, label, attributes, lookup, create, update):
        try:
            current = lookup()
        except exception.NotFound:
            try:
                current = create()
            except exception.Conflict:
                # Another bootstrap or the legacy seeder may have won the
                # create race. Resolve its actual ID before continuing.
                current = lookup()
            else:
                LOG.info('Created %s (%s)', label, current['id'])
                return current
        changes = _changes(current, attributes)
        if changes:
            current = update(current['id'], changes)
            LOG.info('Updated %s (%s)', label, current['id'])
        return current

    @staticmethod
    def _find_unique(list_resources, filters, not_found, label):
        hints = driver_hints.Hints()
        for key, value in filters.items():
            hints.add_filter(key, value, case_sensitive=True)
        # Drivers may leave filters on extra attributes (e.g. service name)
        # unsatisfied. Also pass hints positionally to avoid API list limits.
        matches = [ref for ref in list_resources(hints)
                   if all(ref.get(key) == value
                          for key, value in filters.items())]
        if not matches:
            raise not_found
        if len(matches) != 1:
            raise BootstrapError('Ambiguous %s: multiple matches' % label)
        return matches[0]

    def _lookup_role(self, name):
        return self._find_unique(
            self.role_api.list_roles, {'name': name, 'domain_id': None},
            exception.RoleNotFound(role_id=name), 'global role %s' % name)

    def _domain_id(self, name):
        key = ('domain', name)
        if key not in self._cache:
            try:
                self._cache[key] = self.resource_api.get_domain_by_name(name)
            except exception.DomainNotFound:
                raise BootstrapError(
                    'Domain %s was not found' % name) from None
        return self._cache[key]['id']

    def _role_id(self, name):
        key = ('role', name)
        if key not in self._cache:
            try:
                self._cache[key] = self._lookup_role(name)
            except exception.RoleNotFound:
                raise BootstrapError(
                    'Global role %s was not found' % name) from None
        return self._cache[key]['id']

    def _qualified_id(self, kind, ref):
        key = (kind, ref['domain'], ref['name'])
        if key not in self._cache:
            domain_id = self._domain_id(ref['domain'])
            api = (self.resource_api if kind == 'project'
                   else self.identity_api)
            lookup = getattr(api, 'get_%s_by_name' % kind)
            try:
                self._cache[key] = lookup(ref['name'], domain_id)
            except exception.NotFound:
                raise BootstrapError('%s %s in domain %s was not found' %
                                     (kind.capitalize(), ref['name'],
                                      ref['domain'])) from None
        return self._cache[key]['id']

    def _domain(self, domain):
        attributes = {key: value for key, value in domain.items()
                      if key not in ('id', 'config')}
        ref = self._ensure(
            'domain %s' % domain['name'], attributes,
            lambda: self.resource_api.get_domain_by_name(domain['name']),
            lambda: _create_with_id(self.resource_api.create_domain,
                                    attributes, domain.get('id')),
            self.resource_api.update_domain)
        self._cache[('domain', domain['name'])] = ref
        if 'config' in domain:
            current = self.domain_config_api.get_config_with_sensitive_info(
                ref['id'])
            changes = {}
            for group, options in domain['config'].items():
                changed = _changes(current.get(group, {}), options)
                if changed:
                    changes[group] = changed
            if changes:
                # PATCH semantics preserve options still owned by the seeder.
                self.domain_config_api.update_config(ref['id'], changes)
                LOG.info('Updated configuration for domain %s (%s)',
                         domain['name'], ref['id'])

    def _role(self, role):
        ref = self._ensure(
            'role %s' % role['name'], role,
            lambda: self._lookup_role(role['name']),
            lambda: _create_with_id(self.role_api.create_role, role),
            self.role_api.update_role)
        self._cache[('role', role['name'])] = ref

    @staticmethod
    def _ensure_link(check, create):
        try:
            check()
        except exception.NotFound:
            try:
                create()
            except exception.Conflict:
                check()

    def _inference(self, inference):
        prior_id = self._role_id(inference['prior_role'])
        implied_id = self._role_id(inference['implied_role'])
        self._ensure_link(
            lambda: self.role_api.get_implied_role(prior_id, implied_id),
            lambda: self.role_api.create_implied_role(prior_id, implied_id))

    def _region(self, region):
        attributes = {key: value for key, value in region.items()
                      if key not in ('id', 'parent_region')}
        if 'parent_region' in region:
            attributes['parent_region_id'] = region['parent_region']
        self._ensure(
            'region %s' % region['id'], attributes,
            lambda: self.catalog_api.get_region(region['id']),
            lambda: self.catalog_api.create_region(
                dict(attributes, id=region['id'])),
            self.catalog_api.update_region)

    def _service(self, service):
        attributes = {key: value for key, value in service.items()
                      if key != 'endpoints'}
        filters = {key: service[key] for key in ('name', 'type')}
        label = 'service %s (%s)' % (service['name'], service['type'])
        ref = self._ensure(
            label, attributes,
            lambda: self._find_unique(
                self.catalog_api.list_services, filters,
                exception.ServiceNotFound(service_id=service['name']), label),
            lambda: _create_with_id(self.catalog_api.create_service,
                                    attributes),
            self.catalog_api.update_service)
        for endpoint in service.get('endpoints', []):
            self._endpoint(ref['id'], endpoint)

    def _endpoint(self, service_id, endpoint):
        attributes = {key: value for key, value in endpoint.items()
                      if key != 'region'}
        attributes.update(service_id=service_id, region_id=endpoint['region'])
        filters = {key: attributes[key] for key in
                   ('service_id', 'region_id', 'interface')}
        label = '%s endpoint for service %s in region %s' % (
            endpoint['interface'], service_id, endpoint['region'])
        self._ensure(
            label, attributes,
            lambda: self._find_unique(
                self.catalog_api.list_endpoints, filters,
                exception.EndpointNotFound(endpoint_id=label), label),
            lambda: _create_with_id(self.catalog_api.create_endpoint,
                                    attributes),
            self.catalog_api.update_endpoint)

    def _scoped_resource(self, kind, resource):
        domain_id = self._domain_id(resource['domain'])
        attributes = {key: value for key, value in resource.items()
                      if key != 'domain'}
        attributes['domain_id'] = domain_id
        api = self.resource_api if kind == 'project' else self.identity_api
        lookup = getattr(api, 'get_%s_by_name' % kind)
        create = getattr(api, 'create_%s' % kind)
        update = getattr(api, 'update_%s' % kind)

        def create_resource():
            if kind == 'project':
                return _create_with_id(create, attributes)
            return create(attributes)

        ref = self._ensure(
            '%s %s@%s' % (kind, resource['name'], resource['domain']),
            attributes,
            lambda: lookup(resource['name'], domain_id),
            create_resource, update)
        self._cache[(kind, resource['domain'], resource['name'])] = ref

    def _project(self, project):
        self._scoped_resource('project', project)

    def _user(self, user):
        self._scoped_resource('user', user)

    def _group(self, group):
        self._scoped_resource('group', group)

    def _membership(self, membership):
        user_id = self._qualified_id('user', membership['user'])
        group_id = self._qualified_id('group', membership['group'])
        self._ensure_link(
            lambda: self.identity_api.check_user_in_group(user_id, group_id),
            lambda: self.identity_api.add_user_to_group(user_id, group_id))

    def _assignment(self, assignment):
        role_id = self._role_id(assignment['role'])
        kind = 'user' if 'user' in assignment else 'group'
        principal_id = self._qualified_id(kind, assignment[kind])
        if 'system' in assignment:
            check = getattr(self.assignment_api,
                            'check_system_grant_for_%s' % kind)
            create = getattr(self.assignment_api,
                             'create_system_grant_for_%s' % kind)
            self._ensure_link(lambda: check(principal_id, role_id),
                              lambda: create(principal_id, role_id))
        else:
            grant = {
                'role_id': role_id, kind + '_id': principal_id,
                'inherited_to_projects': assignment.get('inherited', False),
            }
            if 'project' in assignment:
                grant['project_id'] = self._qualified_id(
                    'project', assignment['project'])
            else:
                grant['domain_id'] = self._domain_id(assignment['domain'])
            self._ensure_link(
                lambda: self.assignment_api.get_grant(**grant),
                lambda: self.assignment_api.create_grant(**grant))


def run(path):
    config = load_config(path)
    try:
        managers = backends.load_backends()
    except Exception as error:
        raise BootstrapError('Cannot load Keystone backends (%s)' %
                             type(error).__name__) from error
    Bootstrapper(managers).apply(config)
