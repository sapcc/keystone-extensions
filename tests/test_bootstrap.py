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

import contextlib
import copy
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

import yaml

from keystone.cmd import bootstrap as native_bootstrap
from keystone.common import provider_api
from keystone.common import sql
from keystone import exception
from keystone.identity.backends import ldap
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database

from cc.keystone.cmd import bootstrap


PROVIDERS = provider_api.ProviderAPIs
FIXTURE = Path(__file__).parent / 'fixtures' / 'bootstrap.yaml'


class BootstrapConfigTests(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bootstrap.yaml'
            path.write_text(text, encoding='utf-8')
            return bootstrap.load_config(path)

    def test_load_rendered_format(self):
        config = bootstrap.load_config(FIXTURE)
        self.assertEqual('default', config['domains'][0]['id'])
        self.assertIs(True, config['users'][0]['enabled'])
        self.assertEqual(9, len(config['role_assignments']))

    def test_preserve_ldap_value_types_and_literal_password(self):
        password = 'quote\'" colon: # hash \\ slash\n{{ literal }} ü'
        config = {'domains': [{
            'name': 'ccadmin',
            'config': {
                'identity': {'driver': 'cc_ldap'},
                'ldap': {'password': password, 'use_tls': False,
                         'pool_size': 100, 'user_enabled_default': '512'},
            },
        }]}
        result = self.load(yaml.safe_dump(config))
        self.assertEqual(config, result)
        self.assertIsInstance(
            result['domains'][0]['config']['ldap']['user_enabled_default'],
            str)

    def test_reject_invalid_documents(self):
        for text in ('', '[]', 'roles: {}', 'roles: [{name: 123}]',
                     'users: [{name: admin}]', 'role_assignments: [null]',
                     'roles: []\n---\nroles: []', 'roles: []\nroles: []',
                     '!!python/object:builtins.object {}',
                     'domains: [{name: Default, users: []}]'):
            with self.subTest(text=text):
                self.assertRaises(bootstrap.BootstrapError, self.load, text)

    def test_reject_ambiguous_assignments(self):
        principal = {'name': 'admin', 'domain': 'Default'}
        invalid = [
            {'role': 'admin', 'domain': 'Default'},
            {'role': 'admin', 'user': principal},
            {'role': 'admin', 'user': principal, 'group': principal,
             'domain': 'Default'},
            {'role': 'admin', 'user': principal, 'domain': 'Default',
             'project': principal},
            {'role': 'admin', 'user': principal, 'system': 'all',
             'inherited': True},
            {'role': 'admin', 'user': principal, 'system': 'other'},
            {'role': 'admin', 'user': principal, 'domain': 'Default',
             'inherited': 'false'},
        ]
        for assignment in invalid:
            with self.subTest(assignment=assignment):
                self.assertRaises(
                    bootstrap.BootstrapError, self.load,
                    yaml.safe_dump({'role_assignments': [assignment]}))

    def test_reject_duplicate_declarations_and_region_cycles(self):
        for config in (
            {'roles': [{'name': 'admin'}, {'name': 'admin'}]},
            {'projects': [{'name': 'admin', 'domain': 'Default'}] * 2},
            {'regions': [{'id': 'one', 'parent_region': 'two'},
                         {'id': 'two', 'parent_region': 'one'}]},
        ):
            with self.subTest(config=config):
                self.assertRaises(bootstrap.BootstrapError, self.load,
                                  yaml.safe_dump(config))

    def test_parse_error_does_not_disclose_yaml_contents(self):
        secret = 'private-password-must-not-be-logged'
        with self.assertRaises(bootstrap.BootstrapError) as error:
            self.load('domains: [\n  password: ' + secret)
        self.assertNotIn(secret, str(error.exception))

    def test_invalid_file_is_rejected_before_loading_backends(self):
        with mock.patch.object(bootstrap, 'load_config',
                               side_effect=bootstrap.BootstrapError('bad')), \
                mock.patch.object(bootstrap.backends, 'load_backends') as load:
            self.assertRaises(bootstrap.BootstrapError, bootstrap.run, 'bad')
        load.assert_not_called()


class BootstrapTests(unit.SQLDriverOverrides, unit.TestCase):
    def setUp(self):
        super().setUp()
        self.useFixture(database.Database())
        native = native_bootstrap.Bootstrapper()
        root = default_fixtures.ROOT_DOMAIN
        PROVIDERS.resource_api.create_domain(root['id'], root)
        native.admin_username = 'admin'
        native.admin_password = 'native-admin-password'
        native.project_name = 'admin'
        native.admin_role_name = 'admin'
        native.service_name = 'keystone'
        native.region_id = 'qa-de-1'
        native.public_url = 'https://old.example.test/v3'
        native.bootstrap()
        self.native = native
        self.managers = {name: PROVIDERS[name] for name in (
            'resource_api', 'domain_config_api', 'identity_api',
            'role_api', 'assignment_api', 'catalog_api')}
        self.bootstrap = bootstrap.Bootstrapper(self.managers)
        self.data = bootstrap.load_config(FIXTURE)

    def test_baseline_reuses_native_ids_and_preserves_password(self):
        self.bootstrap.apply(self.data)
        user = PROVIDERS.identity_api.get_user_by_name('admin', 'default')
        project = PROVIDERS.resource_api.get_project_by_name(
            'admin', 'default')
        self.assertEqual(self.native.admin_user_id, user['id'])
        self.assertEqual(self.native.project_id, project['id'])
        self.assertEqual('Openstack Cloud Administrator', user['description'])
        self.assertEqual('Administrator Project', project['description'])
        with self.make_request():
            PROVIDERS.identity_api.authenticate(
                user['id'], 'native-admin-password')
        administrators = PROVIDERS.identity_api.get_group_by_name(
            'administrators', 'default')
        PROVIDERS.identity_api.check_user_in_group(
            user['id'], administrators['id'])
        PROVIDERS.assignment_api.check_system_grant_for_group(
            administrators['id'], self.native.admin_role_id)
        PROVIDERS.assignment_api.get_grant(
            self.native.admin_role_id, group_id=administrators['id'],
            domain_id='default')
        PROVIDERS.role_api.get_implied_role(
            self.native.admin_role_id, self.native.member_role_id)
        self.assertEqual('eu', PROVIDERS.catalog_api.get_region(
            'qa-de-1')['parent_region_id'])
        endpoint = PROVIDERS.catalog_api.get_endpoint(
            self.native.endpoints['public'])
        self.assertEqual('https://identity.example.test/v3', endpoint['url'])
        self.assertEqual(self.native.service_id, endpoint['service_id'])

    def test_second_run_does_not_write(self):
        original = copy.deepcopy(self.data)
        self.bootstrap.apply(self.data)
        writes = []
        with contextlib.ExitStack() as stack:
            for api, methods in (
                ('resource_api', ('create_domain', 'update_domain',
                                  'create_project', 'update_project')),
                ('identity_api', ('create_user', 'update_user', 'create_group',
                                  'update_group', 'add_user_to_group')),
                ('role_api', ('create_role', 'update_role',
                              'create_implied_role')),
                ('catalog_api', ('create_region', 'update_region',
                                 'create_service', 'update_service',
                                 'create_endpoint', 'update_endpoint')),
                ('assignment_api', ('create_grant',
                                    'create_system_grant_for_user',
                                    'create_system_grant_for_group')),
            ):
                for method in methods:
                    manager = self.managers[api]
                    writes.append(stack.enter_context(mock.patch.object(
                        manager, method, wraps=getattr(manager, method))))
            self.bootstrap.apply(self.data)
        for write in writes:
            write.assert_not_called()
        self.assertEqual(original, self.data)

    def test_missing_group_does_not_block_later_grants(self):
        config, driver = self.ldap_config()

        def get_group(name, domain_id):
            if name == 'MISSING_GROUP':
                raise exception.GroupNotFound(group_id=name)
            return {'id': 'directory-local-group', 'name': name}

        driver.get_group_by_name.side_effect = get_group
        self.data['role_assignments'].insert(0, {
            'group': {'name': 'MISSING_GROUP', 'domain': 'ccadmin'},
            'domain': 'ccadmin', 'role': 'admin',
        })
        with mock.patch.object(bootstrap, 'LOG') as log:
            with self.assertRaises(bootstrap.BootstrapError) as error:
                self.bootstrap.apply(self.data)

        PROVIDERS.assignment_api.get_grant(
            self.native.admin_role_id, user_id=self.native.admin_user_id,
            domain_id='default')
        domain = PROVIDERS.resource_api.get_domain_by_name('ccadmin')
        group = PROVIDERS.identity_api.get_group_by_name(
            'CCADMIN_CLOUD_ADMINS', domain['id'])
        project = PROVIDERS.resource_api.get_project_by_name(
            'cloud_admin', domain['id'])
        PROVIDERS.assignment_api.get_grant(
            self.native.admin_role_id, group_id=group['id'],
            project_id=project['id'])
        self.assertIn('1 bootstrap operation(s) failed', str(error.exception))
        self.assertIn('MISSING_GROUP', str(log.error.call_args_list))
        driver.create_group.assert_not_called()

    def test_failed_project_does_not_block_resources_and_can_be_retried(self):
        self.data['projects'].insert(
            0, {'name': 'temporarily-unavailable', 'domain': 'Default'})
        create_project = PROVIDERS.resource_api.create_project
        secret = 'password-must-not-appear-in-bootstrap-errors'

        def fail_one_project(project_id, project):
            if project['name'] == 'temporarily-unavailable':
                raise RuntimeError(secret)
            return create_project(project_id, project)

        with mock.patch.object(PROVIDERS.resource_api, 'create_project',
                               side_effect=fail_one_project), \
                mock.patch.object(bootstrap, 'LOG') as log:
            with self.assertRaises(bootstrap.BootstrapError) as error:
                self.bootstrap.apply(self.data)

        project = PROVIDERS.resource_api.get_project_by_name(
            'service', 'default')
        group = PROVIDERS.identity_api.get_group_by_name(
            'administrators', 'default')
        PROVIDERS.assignment_api.get_grant(
            self.native.admin_role_id, group_id=group['id'],
            project_id=project['id'])
        self.assertIn('1 bootstrap operation(s) failed', str(error.exception))
        self.assertIn('projects[0]', str(log.error.call_args_list))
        self.assertNotIn(secret, str(log.error.call_args_list))
        self.assertNotIn(secret, str(error.exception))

        self.bootstrap.apply(self.data)
        PROVIDERS.resource_api.get_project_by_name(
            'temporarily-unavailable', 'default')
        self.assertEqual(project['id'], PROVIDERS.resource_api.
                         get_project_by_name('service', 'default')['id'])
        self.assertEqual(group['id'], PROVIDERS.identity_api.
                         get_group_by_name('administrators', 'default')['id'])

    def test_failed_endpoint_does_not_block_sibling_endpoints(self):
        self.data['services'].append({'name': 'other', 'type': 'other'})
        with mock.patch.object(PROVIDERS.catalog_api, 'update_endpoint',
                               side_effect=RuntimeError('endpoint failed')), \
                mock.patch.object(bootstrap, 'LOG') as log:
            with self.assertRaises(bootstrap.BootstrapError) as error:
                self.bootstrap.apply(self.data)

        endpoints = [endpoint for endpoint in
                     PROVIDERS.catalog_api.list_endpoints()
                     if endpoint['service_id'] == self.native.service_id]
        self.assertEqual({'public', 'admin', 'internal'},
                         {endpoint['interface'] for endpoint in endpoints})
        services = PROVIDERS.catalog_api.list_services()
        self.assertIn('other', {service['name'] for service in services})
        PROVIDERS.identity_api.get_group_by_name('administrators', 'default')
        self.assertIn('1 bootstrap operation(s) failed', str(error.exception))
        self.assertIn('endpoints[0]', str(log.error.call_args_list))

    def test_failed_domain_config_blocks_only_dependent_identity_work(self):
        config, driver = self.ldap_config()
        driver.get_group_by_name.side_effect = lambda name, domain_id: {
            'id': 'directory-local-' + name, 'name': name}
        self.data['domains'].append({'name': 'later-domain'})
        self.data['groups'].append(
            {'name': 'must-use-ldap', 'domain': 'ccadmin'})
        with mock.patch.object(PROVIDERS.domain_config_api, 'update_config',
                               side_effect=RuntimeError('config failed')), \
                mock.patch.object(bootstrap, 'LOG') as log:
            self.assertRaises(bootstrap.BootstrapError,
                              self.bootstrap.apply, self.data)

        PROVIDERS.resource_api.get_domain_by_name('later-domain')
        PROVIDERS.assignment_api.get_grant(
            self.native.admin_role_id, user_id=self.native.admin_user_id,
            domain_id='default')
        domain = PROVIDERS.resource_api.get_domain_by_name('ccadmin')
        self.assertRaises(exception.GroupNotFound,
                          PROVIDERS.identity_api.get_group_by_name,
                          'must-use-ldap', domain['id'])
        self.assertIn('Identity configuration for domain ccadmin failed',
                      str(log.error.call_args_list))

        self.bootstrap.apply(self.data)
        self.assertEqual(config, PROVIDERS.domain_config_api.
                         get_config_with_sensitive_info(domain['id']))
        group = PROVIDERS.identity_api.get_group_by_name(
            'must-use-ldap', domain['id'])
        self.assertNotEqual('directory-local-must-use-ldap', group['id'])

    def test_consecutive_cli_processes_are_idempotent(self):
        self.ldap_config()
        other_project = unit.new_project_ref(name='cloud_admin',
                                             domain_id='default')
        PROVIDERS.resource_api.create_project(other_project['id'],
                                              other_project)
        root = Path(__file__).resolve().parents[1]
        runner = root / 'tests' / 'fixtures' / 'bootstrap_runner.py'
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            database_path = directory / 'keystone.sqlite'
            # Start both processes from the database populated by native
            # bootstrap, including its existing IDs and password hash.
            with contextlib.closing(sqlite3.connect(database_path)) as target:
                with sql.session_for_read() as session:
                    session.connection().connection.backup(target)

            config_path = directory / 'keystone.conf'
            config_path.write_text(
                '[database]\nconnection = sqlite:///%s\n'
                '[identity]\ndriver = sql\n'
                'domain_specific_drivers_enabled = true\n'
                'domain_configurations_from_database = true\n'
                '[cache]\nenabled = false\n'
                '[fernet_tokens]\nkey_repository = %s\n'
                '[fernet_receipts]\nkey_repository = %s\n' % (
                    database_path,
                    bootstrap.CONF.fernet_tokens.key_repository,
                    bootstrap.CONF.fernet_receipts.key_repository),
                encoding='utf-8')
            bootstrap_path = directory / 'bootstrap.yaml'
            bootstrap_path.write_text(yaml.safe_dump(self.data),
                                      encoding='utf-8')
            command = [sys.executable, str(runner), '--config-file',
                       str(config_path), 'bootstrap', '--bootstrap-file',
                       str(bootstrap_path)]
            env = dict(os.environ)
            env['PYTHONPATH'] = os.pathsep.join(filter(None, (
                str(root), env.get('PYTHONPATH'))))

            snapshots = []
            for run in range(2):
                result = subprocess.run(
                    command, cwd=root, env=env, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, timeout=60)
                self.assertEqual(0, result.returncode,
                                 'Run %s: %s' % (run + 1, result.stdout))
                with contextlib.closing(
                        sqlite3.connect(database_path)) as connection:
                    snapshots.append(list(connection.iterdump()))
                    project_id = connection.execute(
                        'SELECT project.id FROM project '
                        'JOIN project AS domain '
                        'ON project.domain_id = domain.id '
                        'WHERE project.name = ? AND domain.name = ? '
                        'AND domain.is_domain = 1',
                        ('cloud_admin', 'ccadmin')).fetchone()[0]
                    self.assertIn(
                        'Project cloud_admin in domain ccadmin: %s\n' %
                        project_id, result.stdout)
                    if run == 0:
                        # Confirm the first command applied the declarations,
                        # rather than accepting two successful no-op commands.
                        self.assertEqual(2, connection.execute(
                            'SELECT count(*) FROM "group"').fetchone()[0])
                        self.assertEqual(3, connection.execute(
                            'SELECT count(*) FROM endpoint').fetchone()[0])
                        self.assertEqual(9, connection.execute(
                            'SELECT count(*) FROM assignment').fetchone()[0])
                        self.assertEqual(2, connection.execute(
                            'SELECT count(*) FROM system_assignment'
                        ).fetchone()[0])
                        self.assertEqual(1, connection.execute(
                            'SELECT count(*) FROM id_mapping'
                        ).fetchone()[0])

            # This includes every resource, grant, inference, LDAP public-ID
            # mapping, domain configuration value and the admin password hash.
            self.assertEqual(snapshots[0], snapshots[1])

            # Reporting must also work in a fresh process when input validation
            # prevents the normal bootstrap backend initialization.
            for text in (None, 'domains: [', 'projects: {}'):
                with self.subTest(invalid_file=text):
                    if text is None:
                        bootstrap_path.unlink()
                    else:
                        bootstrap_path.write_text(text, encoding='utf-8')
                    result = subprocess.run(
                        command, cwd=root, env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True, timeout=60)
                    self.assertEqual(1, result.returncode, result.stdout)
                    self.assertIn(
                        'Project cloud_admin in domain ccadmin: %s\n' %
                        project_id, result.stdout)
                    with contextlib.closing(
                            sqlite3.connect(database_path)) as connection:
                        self.assertEqual(snapshots[1],
                                         list(connection.iterdump()))

    def test_unlisted_resources_and_grants_are_preserved(self):
        project = unit.new_project_ref(domain_id='default')
        PROVIDERS.resource_api.create_project(project['id'], project)
        PROVIDERS.assignment_api.create_grant(
            self.native.reader_role_id, user_id=self.native.admin_user_id,
            project_id=project['id'])
        self.bootstrap.apply(self.data)
        self.assertEqual(project['id'], PROVIDERS.resource_api.get_project(
            project['id'])['id'])
        PROVIDERS.assignment_api.get_grant(
            self.native.reader_role_id, user_id=self.native.admin_user_id,
            project_id=project['id'])

    def test_same_names_are_resolved_in_their_domains(self):
        domain = unit.new_domain_ref(name='ccadmin')
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        local_role = unit.new_role_ref(name='admin', domain_id=domain['id'])
        PROVIDERS.role_api.create_role(local_role['id'], local_role)
        self.data['domains'].append({'name': 'ccadmin', 'id': 'unused-hint'})
        self.data['projects'].append({'name': 'admin', 'domain': 'ccadmin'})
        self.data['users'].append({'name': 'admin', 'domain': 'ccadmin'})
        self.data['role_assignments'].append({
            'user': {'name': 'admin', 'domain': 'ccadmin'},
            'project': {'name': 'admin', 'domain': 'ccadmin'}, 'role': 'admin',
            'inherited': True,
        })
        self.bootstrap.apply(self.data)
        user = PROVIDERS.identity_api.get_user_by_name('admin', domain['id'])
        project = PROVIDERS.resource_api.get_project_by_name(
            'admin', domain['id'])
        self.assertNotEqual(self.native.admin_user_id, user['id'])
        self.assertNotEqual(self.native.project_id, project['id'])
        PROVIDERS.assignment_api.get_grant(
            self.native.admin_role_id, user_id=user['id'],
            project_id=project['id'], inherited_to_projects=True)
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain, 'unused-hint')

    def ldap_config(self):
        self.config_fixture.config(
            group='identity', domain_specific_drivers_enabled=True,
            domain_configurations_from_database=True)
        config = {
            'identity': {'driver': 'ldap'},
            'ldap': {'url': 'ldap://example.test', 'password': 'secret\n"',
                     'use_pool': True, 'pool_size': 100,
                     'user_enabled_default': '512'},
        }
        self.data['domains'].append({'name': 'ccadmin', 'config': config})
        self.data['projects'].append(
            {'name': 'cloud_admin', 'domain': 'ccadmin'})
        self.data['role_assignments'].extend([
            {'group': {'name': 'CCADMIN_CLOUD_ADMINS', 'domain': 'ccadmin'},
             'project': {'name': 'cloud_admin', 'domain': 'ccadmin'},
             'role': 'admin'},
            {'group': {'name': 'CCADMIN_CLOUD_ADMINS', 'domain': 'ccadmin'},
             'domain': 'ccadmin', 'role': 'cloud_identity_viewer',
             'inherited': True},
        ])
        driver = mock.Mock(spec=ldap.Identity)
        driver.is_sql = False
        driver.is_domain_aware.return_value = False
        driver.generates_uuids.return_value = False
        driver.get_group_by_name.return_value = {
            'id': 'directory-local-group', 'name': 'CCADMIN_CLOUD_ADMINS'}
        patcher = mock.patch.object(PROVIDERS.identity_api.domain_configs,
                                    '_load_driver', return_value=driver)
        patcher.start()
        self.addCleanup(patcher.stop)
        return config, driver

    def test_ldap_grants_use_manager_public_ids_after_configuration(self):
        config, driver = self.ldap_config()
        self.bootstrap.apply(self.data)
        domain = PROVIDERS.resource_api.get_domain_by_name('ccadmin')
        self.assertEqual(config,
                         PROVIDERS.domain_config_api.
                         get_config_with_sensitive_info(domain['id']))
        driver.get_group_by_name.assert_called_with(
            'CCADMIN_CLOUD_ADMINS', domain['id'])
        group = PROVIDERS.identity_api.get_group_by_name(
            'CCADMIN_CLOUD_ADMINS', domain['id'])
        self.assertNotEqual('directory-local-group', group['id'])
        mapping = PROVIDERS.id_mapping_api.get_id_mapping(group['id'])
        self.assertEqual('directory-local-group', mapping['local_id'])
        self.assertEqual(domain['id'], mapping['domain_id'])
        project = PROVIDERS.resource_api.get_project_by_name(
            'cloud_admin', domain['id'])
        PROVIDERS.assignment_api.get_grant(
            self.native.admin_role_id, group_id=group['id'],
            project_id=project['id'])
        viewer = next(role for role in PROVIDERS.role_api.list_roles()
                      if role['name'] == 'cloud_identity_viewer')
        PROVIDERS.assignment_api.get_grant(
            viewer['id'], group_id=group['id'], domain_id=domain['id'],
            inherited_to_projects=True)
        driver.create_group.assert_not_called()
        driver.update_group.assert_not_called()
        with mock.patch.object(PROVIDERS.domain_config_api,
                               'update_config') as update:
            self.bootstrap.apply(self.data)
        update.assert_not_called()

    def test_domain_config_updates_merge_and_keep_types(self):
        config, driver = self.ldap_config()
        domain = unit.new_domain_ref(name='ccadmin')
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        PROVIDERS.domain_config_api.create_config(domain['id'], {
            'identity': {'driver': 'ldap'},
            'ldap': {'password': 'old', 'pool_size': '100',
                     'user_enabled_default': 512, 'page_size': 500},
        })
        self.bootstrap.apply(self.data)
        result = PROVIDERS.domain_config_api.get_config_with_sensitive_info(
            domain['id'])
        self.assertEqual(500, result['ldap']['page_size'])
        self.assertEqual(config['ldap']['password'],
                         result['ldap']['password'])
        self.assertIsInstance(result['ldap']['pool_size'], int)
        self.assertIsInstance(result['ldap']['user_enabled_default'], str)

    def test_missing_ldap_group_fails_without_creating_it(self):
        config, driver = self.ldap_config()
        driver.get_group_by_name.side_effect = exception.GroupNotFound(
            group_id='CCADMIN_CLOUD_ADMINS')
        with mock.patch.object(bootstrap, 'LOG') as log:
            with self.assertRaises(bootstrap.BootstrapError) as error:
                self.bootstrap.apply(self.data)
        self.assertIn('2 bootstrap operation(s) failed', str(error.exception))
        self.assertIn('CCADMIN_CLOUD_ADMINS', str(log.error.call_args_list))
        self.assertIn('ccadmin', str(log.error.call_args_list))
        driver.create_group.assert_not_called()

    def test_database_domain_driver_configuration_is_required(self):
        self.data['domains'].append({
            'name': 'ccadmin', 'config': {'identity': {'driver': 'ldap'}}})
        with mock.patch.object(PROVIDERS.resource_api,
                               'create_domain') as create:
            self.assertRaises(bootstrap.BootstrapError,
                              self.bootstrap.apply, self.data)
        create.assert_not_called()

    def test_duplicate_services_fail_instead_of_picking_an_id(self):
        service_id = uuid.uuid4().hex
        PROVIDERS.catalog_api.create_service(service_id, {
            'id': service_id, 'name': 'keystone', 'type': 'identity'})
        self.assertRaises(bootstrap.BootstrapError,
                          self.bootstrap.apply, self.data)

    def test_service_lookup_filters_names_as_well_as_type(self):
        other_id = uuid.uuid4().hex
        PROVIDERS.catalog_api.create_service(other_id, {
            'id': other_id, 'name': 'other', 'type': 'identity'})
        self.bootstrap.apply(self.data)
        self.assertEqual('Openstack Identity', PROVIDERS.catalog_api.
                         get_service(self.native.service_id)['description'])
        self.assertNotIn('description',
                         PROVIDERS.catalog_api.get_service(other_id))

    def test_duplicate_endpoints_fail_instead_of_picking_an_id(self):
        endpoint_id = uuid.uuid4().hex
        PROVIDERS.catalog_api.create_endpoint(endpoint_id, {
            'id': endpoint_id, 'service_id': self.native.service_id,
            'interface': 'public', 'region_id': 'qa-de-1',
            'url': 'http://duplicate.example.test/v3'})
        self.assertRaises(bootstrap.BootstrapError,
                          self.bootstrap.apply, self.data)

    def test_invalid_grant_is_rejected_before_writes(self):
        self.data['role_assignments'].append({'role': 'admin'})
        with mock.patch.object(PROVIDERS.resource_api,
                               'update_domain') as update:
            self.assertRaises(bootstrap.BootstrapError,
                              self.bootstrap.apply, self.data)
        update.assert_not_called()
