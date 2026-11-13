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
import types
import unittest
from unittest import mock

from cc.keystone.cmd import cli
from cc.keystone.cmd import doctor


class TestDoctorIgnore(unittest.TestCase):
    """Exercise ignore handling without running any Keystone checks."""

    def setUp(self):
        super().setUp()
        self.parser = argparse.ArgumentParser()
        cli.add_command_parsers(self.parser.add_subparsers())

    def _symptom(self, name, found=True):
        symptom = mock.Mock(return_value=found)
        symptom.__name__ = name
        symptom.__doc__ = 'Warning for %s.' % name
        return symptom

    def _run_doctor(self, symptoms, *arguments):
        command = self.parser.parse_args(['doctor', *arguments])
        conf = types.SimpleNamespace(debug=False, command=command)
        with mock.patch.object(doctor, 'CONF', conf), \
                mock.patch.object(doctor.doctor, 'gather_symptoms',
                                  return_value=symptoms) as gather, \
                mock.patch('builtins.print'):
            with self.assertRaises(SystemExit) as result:
                command.cmd_class.main()

        gather.assert_called_once_with()
        for symptom in symptoms:
            symptom.assert_called_once_with()
        return result.exception.code

    def test_parser_defaults_to_no_ignored_symptoms(self):
        command = self.parser.parse_args(['doctor'])
        self.assertIs(cli.Doctor, command.cmd_class)
        self.assertEqual([], command.ignore)

    def test_parser_accepts_repeatable_ignore(self):
        command = self.parser.parse_args([
            'doctor', '--ignore', 'symptom_first',
            '--ignore', 'symptom_second',
        ])
        self.assertEqual(['symptom_first', 'symptom_second'], command.ignore)

    def test_no_ignore_runs_all_checks_and_preserves_failure(self):
        symptoms = [self._symptom('symptom_first'),
                    self._symptom('symptom_second')]
        status = self._run_doctor(symptoms)
        self.assertEqual(1, status)

    def test_ignored_symptom_still_runs(self):
        symptom = self._symptom('symptom_ignored')
        status = self._run_doctor(
            [symptom], '--ignore', 'symptom_ignored')
        self.assertEqual(0, status)

    def test_multiple_ignored_symptoms_allow_success(self):
        symptoms = [self._symptom('symptom_first'),
                    self._symptom('symptom_second')]
        status = self._run_doctor(
            symptoms, '--ignore', 'symptom_first',
            '--ignore', 'symptom_second')
        self.assertEqual(0, status)

    def test_unignored_symptom_keeps_failure_regardless_of_order(self):
        for ignored_first in (False, True):
            with self.subTest(ignored_first=ignored_first):
                ignored = self._symptom('symptom_ignored')
                unignored = self._symptom('symptom_unignored')
                symptoms = ([ignored, unignored] if ignored_first
                            else [unignored, ignored])
                status = self._run_doctor(
                    symptoms, '--ignore', 'symptom_ignored')
                self.assertEqual(1, status)

    def test_ignore_requires_exact_symptom_name(self):
        for name in ('example', 'symptom_', 'symptom_example_extra',
                     'SYMPTOM_EXAMPLE', 'symptom_unknown'):
            with self.subTest(ignore=name):
                symptom = self._symptom('symptom_example')
                status = self._run_doctor([symptom], '--ignore', name)
                self.assertEqual(1, status)

    def test_healthy_check_runs_successfully_with_or_without_ignore(self):
        for arguments in ((), ('--ignore', 'symptom_healthy')):
            with self.subTest(arguments=arguments):
                symptom = self._symptom('symptom_healthy', found=False)
                status = self._run_doctor([symptom], *arguments)
                self.assertEqual(0, status)

    def test_duplicate_ignore_does_not_repeat_check(self):
        symptom = self._symptom('symptom_ignored')
        status = self._run_doctor(
            [symptom], '--ignore', 'symptom_ignored',
            '--ignore', 'symptom_ignored')
        self.assertEqual(0, status)

    def test_no_checks_exits_successfully(self):
        status = self._run_doctor([])
        self.assertEqual(0, status)


if __name__ == '__main__':
    unittest.main()
