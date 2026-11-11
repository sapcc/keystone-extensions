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

import argparse
import sys
import types
import unittest
from unittest import mock


# The kubernetes client is a runtime dependency of the module under test but
# is not required for exercising the logic covered here, so provide a light
# stub that satisfies ``from kubernetes import client, config`` at import time.
def _install_kubernetes_stub():
    if 'kubernetes' in sys.modules:
        return
    k8s = types.ModuleType('kubernetes')
    k8s.client = types.ModuleType('kubernetes.client')
    k8s.config = types.ModuleType('kubernetes.config')
    sys.modules['kubernetes'] = k8s
    sys.modules['kubernetes.client'] = k8s.client
    sys.modules['kubernetes.config'] = k8s.config


_install_kubernetes_stub()

from cc.keystone.cmd import cli  # noqa: E402
from keystone import exception  # noqa: E402


class TestRepairAssignmentsMessage(unittest.TestCase):
    """RepairAssignments must log the actual error text for orphans."""

    def test_orphaned_user_logs_exception_text(self):
        identity_api = mock.Mock()
        resource_api = mock.Mock()
        assignment_api = mock.Mock()

        resource_api.list_domains.return_value = []
        assignment_api.list_role_assignments.return_value = [
            {'user_id': 'u1'}]
        identity_api.get_user.side_effect = exception.UserNotFound(
            user_id='u1')

        backends = {
            'identity_api': identity_api,
            'resource_api': resource_api,
            'assignment_api': assignment_api,
        }

        conf = mock.Mock()
        conf.command.dry_run = True

        with mock.patch.object(cli.backends, 'load_backends',
                               return_value=backends), \
                mock.patch.object(cli, 'CONF', conf), \
                mock.patch.object(cli, 'LOG') as log:
            cli.RepairAssignments.main()

        self.assertTrue(log.warning.called)
        logged = log.warning.call_args[0][0]
        # The real exception text must be present; the previous code logged
        # the always-None ``message`` attribute instead.
        self.assertIn('Could not find user', logged)
        self.assertNotIn('None ->', logged)


class TestRotateSecretKeys(unittest.TestCase):
    """RotateSecretKeys must complete when annotations are present."""

    def _make_secret(self, annotations):
        secret = types.SimpleNamespace()
        secret.data = {'0': b'key-zero', '1': b'key-one'}
        secret.metadata = types.SimpleNamespace(
            name='keystone-fernet',
            namespace='monsoon3',
            annotations=annotations,
            resource_version='1',
        )
        return secret

    def test_rotation_completes_with_annotations(self):
        secret = self._make_secret({'max_active_keys': '3'})

        api_instance = mock.Mock()
        api_instance.read_namespaced_secret.return_value = secret
        api_instance.replace_namespaced_secret.return_value = secret

        client = mock.Mock()
        client.CoreV1Api.return_value = api_instance
        config = mock.Mock()

        conf = mock.Mock()
        conf.command.kubeconfig = '/dev/null'
        conf.command.secret_name = 'keystone-fernet'
        conf.command.secret_namespace = 'monsoon3'
        conf.command.dry_run = False

        with mock.patch.object(cli, 'client', client), \
                mock.patch.object(cli, 'config', config), \
                mock.patch.object(cli, 'CONF', conf):
            cli.RotateSecretKeys.main()

        # With the max_active_keys annotation present the command must run to
        # completion and persist the rotated secret. The previous code raised
        # AttributeError on dict.has_key, which the broad except swallowed, so
        # the secret was never written back.
        api_instance.replace_namespaced_secret.assert_called_once()


class TestBootstrapCommand(unittest.TestCase):
    def test_bootstrap_parser_uses_mounted_file_by_default(self):
        parser = argparse.ArgumentParser()
        cli.add_command_parsers(parser.add_subparsers())
        args = parser.parse_args(['bootstrap'])
        self.assertIs(cli.Bootstrap, args.cmd_class)
        self.assertEqual('/etc/keystone/bootstrap.yaml', args.bootstrap_file)
        args = parser.parse_args(
            ['bootstrap', '--bootstrap-file', 'local.yaml'])
        self.assertEqual('local.yaml', args.bootstrap_file)

    def test_bootstrap_runs_consumer(self):
        conf = types.SimpleNamespace(command=types.SimpleNamespace(
            bootstrap_file='/etc/keystone/bootstrap.yaml'))
        with mock.patch.object(cli, 'CONF', conf), \
                mock.patch.object(cli.bootstrap, 'run') as run:
            cli.Bootstrap.main()
        run.assert_called_once_with('/etc/keystone/bootstrap.yaml')

    def test_bootstrap_failure_exits_nonzero(self):
        conf = types.SimpleNamespace(command=types.SimpleNamespace(
            bootstrap_file='missing.yaml'))
        with mock.patch.object(cli, 'CONF', conf), \
                mock.patch.object(
                    cli.bootstrap, 'run',
                    side_effect=cli.bootstrap.BootstrapError('missing file')):
            with self.assertRaises(SystemExit) as error:
                cli.Bootstrap.main()
        self.assertEqual(1, error.exception.code)


if __name__ == '__main__':
    unittest.main()
