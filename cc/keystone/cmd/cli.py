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

from __future__ import absolute_import
from __future__ import print_function

from builtins import input

import datetime
import re

import pbr.version
import base64
from oslo_config import cfg
from oslo_log import log

import keystone.conf
from keystone import exception
from keystone.common import driver_hints
from keystone.common import sql
from keystone.identity.mapping_backends.sql import IDMapping
from keystone.server import backends
from cryptography import fernet

from kubernetes import client, config
import pyredis

from ..middleware import lifesaver_utils

CID_REGEX = r'^[C-D|I]\d+$'
T_REGEX = r'^T[A-F0-9]+$'

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


class BaseApp(object):
    name = None

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = subparsers.add_parser(cls.name, help=cls.__doc__)
        parser.set_defaults(cmd_class=cls)
        return parser

class UserScore(BaseApp):
    """Get Lifesaver score"""

    name = 'score_get'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(UserScore, cls).add_argument_parser(subparsers)
        parser.add_argument('--user', default=None, required=True,
                            help='Get lifesaver credit score of a given user')
        return parser

    @staticmethod
    def main():
        utils = lifesaver_utils.LifesaverUtils(conf={})
        user = utils.normalize(CONF.command.user)
        user_score = utils.get_user_score(user)

        print(user_score.get())


class RepairAssignments(BaseApp):
    name = 'repair_assignments'

    def __init__(self):
        super(RepairAssignments, self).__init__()

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(RepairAssignments, cls).add_argument_parser(subparsers)
        parser.add_argument('--dry-run', default=False, action='store_true',
                            help='Only diagnose, no actual deletion.')
        parser.add_argument('--user-tolerance-days', default=14,
                            help=('How many days not to delete orphaned '
                                  'user\'s assignemnts.'))
        parser.add_argument('--redis',
                            help='Redis instance to use.')
        return parser

    @staticmethod
    def main():
        # caches
        domain_cache = {}
        project_cache = {}
        user_cache = {}
        group_cache = {}
        redis = pyredis.Client(CONF.command.redis)

        def get_domain(id):
            result = None
            if id not in domain_cache:
                domain = resource_manager.get_domain(id)
                if domain:
                    result = domain_cache[id] = domain['name']
            else:
                result = domain_cache[id]
            return result

        def get_project(id):
            result = None
            if id not in project_cache:
                project = resource_manager.get_project(id)
                if project:
                    result = project_cache[id] = project['name']
            else:
                result = project_cache[id]
            return result

        def get_user(id):
            result = None
            if id not in user_cache:
                user = identity_api.get_user(id)
                if user:
                    result = user_cache[id] = user['name']
            else:
                result = user_cache[id]
            return result

        def get_or_set_user_timestamp(id, dry_run=False):
            PREFIX = 'user_timestamp'
            timestamp = float(redis.get(f'{PREFIX}:{id}'))
            if timestamp:
                timestamp = datetime.datetime.fromtimestamp(timestamp)
            else:
                timestamp = datetime.datetime.now()
                if dry_run:
                    LOG.warning(
                        f"User {id} -> does not exist since now")
                else:
                    redis.set(f'{PREFIX}:{id}', timestamp.timestamp())
            return timestamp

        def get_group(id):
            result = None
            if id not in group_cache:
                group = identity_api.get_group(id)
                if group:
                    result = group_cache[id] = group['name']
            else:
                result = group_cache[id]
            return result

        drivers = backends.load_backends()
        identity_api = drivers['identity_api']
        resource_manager = drivers['resource_api']
        assignment_manager = drivers['assignment_api']

        LOG.info("repairing orphaned role-assignments...")

        # load all users & groups once, so their id's are in the mapping table
        domains = resource_manager.list_domains(driver_hints.Hints())
        for domain in domains:
            identity_api.list_users(domain_scope=domain['id'])
            identity_api.list_groups(domain_scope=domain['id'])
        assignments = assignment_manager.list_role_assignments()

        for assignment in assignments:
            try:
                if 'project_id' in assignment:
                    get_project(assignment['project_id'])
                elif 'domain_id' in assignment:
                    get_domain(assignment['domain_id'])
                if 'user_id' in assignment:
                    get_user(assignment['user_id'])
                if 'group_id' in assignment:
                    get_group(assignment['group_id'])
            except exception.UserNotFound as e:
                # user might disappear from ldap for some reason, but also
                # might reappear. In order not to break their workflow, we give
                # a certain tolerance to their non-existence. The tolerance
                # is implemented via a timestamp stored for that user.
                timestamp = get_or_set_user_timestamp(
                    assignment['user_id'],
                    dry_run=CONF.command.dry_run)
                delta = (datetime.datetime.now() - timestamp).days
                if delta > CONF.command.user_tolerance_days:
                    if CONF.command.dry_run:
                        LOG.warning(
                            "%s -> found orphaned role-assignments for user %s (%s)" % (
                                e.message, assignment['user_id'], assignment))
                    else:
                        LOG.warning(
                            "%s -> deleting role-assignments for user %s (%s)" % (
                            e.message, assignment['user_id'], assignment))
                        assignment_manager.driver.delete_user_assignments(
                            assignment['user_id'])
                else:
                    LOG.warning(
                        ("%s -> orphaned role-assignments for user %s "
                            "(%s) is tolerated for %s days") % (
                                e.message, assignment['user_id'], assignment, delta))
            except exception.GroupNotFound as e:
                if CONF.command.dry_run:
                    LOG.warning(
                        "%s -> found orphaned role-assignments for group %s (%s)" % (
                            e.message, assignment['group_id'], assignment))
                else:
                    LOG.warning(
                        "%s -> deleting role-assignments for group %s (%s)" % (
                            e.message, assignment['group_id'], assignment))
                    assignment_manager.driver.delete_group_assignments(
                        assignment['group_id'])

            except exception.DomainNotFound as e:
                if CONF.command.dry_run:
                    LOG.warning(
                        "%s -> found orphaned role-assignments for domain %s (%s)" % (
                            e.message, assignment['domain_id'],
                            assignment))
                else:
                    LOG.warning(
                        "%s -> deleting role-assignments for domain %s (%s)" % (
                            e.message, assignment['domain_id'],
                            assignment))
                    assignment_manager.driver.delete_domain_assignments(
                        assignment['domain_id'])

            except exception.ProjectNotFound as e:
                if CONF.command.dry_run:
                    LOG.warning(
                        "%s -> found orphaned role-assignments for project %s (%s)" % (
                            e.message, assignment['project_id'],
                            assignment))
                else:
                    LOG.warning(
                        "%s -> deleting role-assignments for project %s (%s)" % (
                            e.message, assignment['project_id'],
                            assignment))
                    assignment_manager.driver.delete_project_assignments(
                        assignment['project_id'])

            except Exception as e:
                LOG.error("%s %s" % (e, assignment))

        LOG.info("repairing orphaned role-assignments done.")


class RepairIdMappings(BaseApp):
    name = 'repair_id_mappings'

    def __init__(self):
        super(RepairIdMappings, self).__init__()

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(RepairIdMappings, cls).add_argument_parser(subparsers)
        parser.add_argument('--dry-run', default=False, action='store_true',
                            help='Only diagnose, no actual deletion.')
        return parser

    @staticmethod
    def main():
        # caches
        user_cache = {}
        domain_cache = {}

        def get_user(id):
            result = None
            if id not in user_cache:
                user = identity_api.get_user(id)
                if user:
                    result = user_cache[id] = user
            else:
                result = user_cache[id]
            return result

        def get_domain(id):
            result = None
            if id not in domain_cache:
                domain = resource_manager.get_domain(id)
                if domain:
                    result = domain_cache[id] = domain['name']
            else:
                result = domain_cache[id]
            return result

        def delete_mapping(entry):
            LOG.info("Deleting mapping %s in domain %s" % (
                entry['local_id'], get_domain(entry['domain_id'])))
            if not CONF.command.dry_run:
                mapping_manager.purge_mappings(entry)

        drivers = backends.load_backends()
        identity_api = drivers['identity_api']
        resource_manager = drivers['resource_api']
        mapping_manager = drivers['id_mapping_api']
        assignment_manager = drivers['assignment_api']

        # load all users once, so their id's are in the mapping table
        domains = resource_manager.list_domains(driver_hints.Hints())
        for domain in domains:
            identity_api.list_users(domain_scope=domain['id'])

        # load all id-mappings
        mappings = []
        with sql.session_for_read() as session:
            query = session.query(IDMapping).filter_by(entity_type='user')
            for entry in query:
                mappings.append(entry.to_dict())

        for entry in mappings:
            try:
                user = get_user(entry['public_id'])
                domain = get_domain(user['domain_id'])
                if domain not in ['cc3test', 'Default']:
                    if entry['local_id'] != user['name'].strip().upper():
                        roles = assignment_manager.list_role_assignments(
                            user_id=entry['public_id'])
                        if len(roles) > 0:
                            LOG.error("User %s@%s (%s) has roles: %s" % (
                                entry['local_id'], get_domain(entry['domain_id']),
                                entry['public_id'], roles))
                        else:
                            delete_mapping(entry)
                    elif not re.match(CID_REGEX, user['name']):
                        if not re.match(T_REGEX, user['name']):
                            LOG.error("Invalid username %s@%s" % (
                                entry['local_id'], get_domain(entry['domain_id'])))

            except exception.UserNotFound:
                roles = assignment_manager.list_role_assignments(
                    user_id=entry['public_id'])
                if len(roles) > 0:
                    LOG.error("User %s@%s (%s) has roles: %s" % (
                        entry['local_id'], get_domain(entry['domain_id']),
                        entry['public_id'], roles))
                else:
                    delete_mapping(entry)


class RotateSecretKeys(BaseApp):
    name = 'rotate_secret_keys'

    def __init__(self):
        super(RotateSecretKeys, self).__init__()

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(RotateSecretKeys, cls).add_argument_parser(subparsers)
        parser.add_argument('--dry-run', default=False, action='store_true',
                            help='Only diagnose, no actual key rotation.')
        parser.add_argument('--kubeconfig', default='~/.kube/config', help='Kubernetes kubeconfig.')
        parser.add_argument('--secret-namespace', default='monsoon3', help='Kubernetes namespace.')
        parser.add_argument('--secret-name', default='keystone-fernet', help='Kubernetes secret name.')
        return parser

    @staticmethod
    def main():
        def load_keys(secret):
            keys = dict()
            for filename in secret.data.keys():
                try:
                    key_id = int(filename)
                except ValueError:  # nosec : name is not a number
                    pass
                else:
                    key = secret.data[filename]
                    if len(key) == 0:
                        LOG.warning('Ignoring empty key found in key secret: %s', filename)
                        continue
                    keys[key_id] = key
            return keys

        def rotate_secret_keys(secret):
            LOG.info('Starting key rotation for secret "%(name)s" in namespace "%(namespace)s" with %(count)s keys: '
                     '%(list)s', {
                         'name': secret.metadata.name,
                         'namespace': secret.metadata.namespace,
                         'count': len(secret.data),
                         'list': list(secret.data.values())})

            # read the list of keys
            keys = load_keys(secret)

            current_primary_key = max(keys.keys())
            LOG.info('Current primary key is: %s %s' % (current_primary_key, keys[current_primary_key]))
            new_primary_key = current_primary_key + 1
            LOG.info('Next primary key will be: %s', new_primary_key)

            # promote the next primary key to be the primary
            keys[new_primary_key] = keys.pop(0)
            LOG.info('Promoted key 0 to be the primary: %s %s' % (new_primary_key, keys[new_primary_key]))

            if secret.metadata.annotations.has_key('max_active_keys'):
                max_active_keys = int(secret.metadata.annotations['max_active_keys'])

                # purge excess keys
                key_list = sorted(keys.keys(), reverse=True)
                while len(key_list) > (max_active_keys - 1):
                    index_to_purge = key_list.pop()
                    key_to_purge = keys[index_to_purge]
                    LOG.info('Excess key to purge: %s', key_to_purge)
                    keys.pop(index_to_purge)

            # next key
            key = fernet.Fernet.generate_key()
            keys[0] = base64.b64encode(key)
            LOG.info('Becomes a valid new key: %s', keys[0])

            return keys

        try:
            # Configs can be set in Configuration class directly or using helper utility
            config.load_kube_config(config_file=CONF.command.kubeconfig)

            api_instance = client.CoreV1Api()

            secret = api_instance.read_namespaced_secret(name=CONF.command.secret_name,
                                                         namespace=CONF.command.secret_namespace)
            if secret:
                new_keys = rotate_secret_keys(secret)
                if not CONF.command.dry_run:
                    LOG.info(
                        'Updating secret "%(name)s" in namespace "%(namespace)s" with %(count)s keys: '
                        '%(list)s', {
                            'name': secret.metadata.name,
                            'namespace': secret.metadata.namespace,
                            'count': len(new_keys),
                            'list': list(new_keys.values())})

                    secret.data = new_keys
                    secret = api_instance.replace_namespaced_secret(name=CONF.command.secret_name,
                                                                  namespace=CONF.command.secret_namespace,
                                                                  body=secret)
                    LOG.info("Update done. New resource version: %s" % secret.metadata.resource_version)

        except Exception as e:
            LOG.error("Command failed %s" % e)


class FernetTokenDoctor(BaseApp):
    name = 'fernet_token_doctor'

    def __init__(self):
        super(FernetTokenDoctor, self).__init__()

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(FernetTokenDoctor, cls).add_argument_parser(subparsers)
        return parser

    @staticmethod
    def main():
        try:
            token_id = input("Enter token: ")

            drivers = backends.load_backends()
            token_provider_api = drivers['token_provider_api']

            token = token_provider_api._validate_token(token_id)

            print("user: %s" % token.user)
            print("issued-at: %s" % token.issued_at)
            print("expires-at: %s" % token.expires_at)

            if token.domain_scoped:
                print("domain-scoped token")
                print("domain: %s" % token.domain)
            elif token.project_scoped:
                print("project-scoped token")
                print("project: %s" % token.project)
            elif token.unscoped:
                print("un-scoped token")
            elif token.system_scoped:
                print("system-scoped token")
            elif token.oauth_scoped:
                print("oauth-scoped token")
                print("token: %s" % token.access_token)
            elif token.trust_scoped:
                print("trust-scoped token")
                print("trust: %s" % token.trust)

            print("roles: %s" % token.roles)

            try:
                token_provider_api.validate_token(token_id)
                print("token is valid")
            except Exception as e:
                print("token is not valid: %s" % e)
        except Exception as e:
            print("failed: %s" % e)


CMDS = [
    RepairAssignments,
    RepairIdMappings,
    RotateSecretKeys,
    FernetTokenDoctor,
    UserScore,
]


def add_command_parsers(subparsers):
    for cmd in CMDS:
        cmd.add_argument_parser(subparsers)


command_opt = cfg.SubCommandOpt('command',
                                title='Commands',
                                help='Available commands',
                                handler=add_command_parsers)


def main(argv=None, config_files=None):
    CONF.register_cli_opt(command_opt)

    keystone.conf.configure()
    sql.initialize()
    keystone.conf.set_default_for_default_log_levels()

    CONF(args=argv[1:],
         project='keystone',
         version=pbr.version.VersionInfo('keystone').version_string(),
         usage='%(prog)s [' + '|'.join([cmd.name for cmd in CMDS]) + ']',
         default_config_files=config_files)
    keystone.conf.setup_logging()
    CONF.command.cmd_class.main()
