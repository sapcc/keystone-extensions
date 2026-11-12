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

"""The deployment-rendered, domain-qualified bootstrap document."""

import jsonschema
import yaml


class BootstrapError(Exception):
    """A bootstrap failure whose message is safe to log."""


def _object(properties, required=()):
    schema = {'type': 'object', 'properties': properties,
              'additionalProperties': False}
    if required:
        schema['required'] = list(required)
    return schema


def _array(items):
    return {'type': 'array', 'items': items}


_NAME = {'type': 'string', 'minLength': 1}
_DESCRIPTION = {'type': 'string'}
_ENABLED = {'type': 'boolean'}
_REFERENCE = _object({'name': _NAME, 'domain': _NAME}, ('name', 'domain'))
_DOMAIN_CONFIG = {
    'type': 'object', 'minProperties': 1,
    'additionalProperties': {
        'type': 'object', 'minProperties': 1,
        'additionalProperties': {
            'type': ['string', 'number', 'boolean', 'array'],
            'items': {'type': 'string'},
        },
    },
}
_ENDPOINT = _object({
    'interface': {'enum': ['public', 'internal', 'admin']},
    'region': _NAME, 'url': _NAME, 'enabled': _ENABLED,
}, ('interface', 'region', 'url'))
_ASSIGNMENT = _object({
    'role': _NAME, 'user': _REFERENCE, 'group': _REFERENCE,
    'domain': _NAME, 'project': _REFERENCE,
    'system': {'enum': ['all']}, 'inherited': {'type': 'boolean'},
}, ('role',))
_ASSIGNMENT['allOf'] = [
    {'oneOf': [{'required': ['user']}, {'required': ['group']}]},
    {'oneOf': [{'required': ['domain']}, {'required': ['project']},
               {'required': ['system']}]},
    {'not': {'required': ['system', 'inherited'],
             'properties': {'inherited': {'enum': [True]}}}},
]
_SCHEMA = _object({
    'roles': _array(_object({
        'name': _NAME, 'description': _DESCRIPTION,
    }, ('name',))),
    'role_inferences': _array(_object({
        'prior_role': _NAME, 'implied_role': _NAME,
    }, ('prior_role', 'implied_role'))),
    'regions': _array(_object({
        'id': _NAME, 'description': _DESCRIPTION,
        'parent_region': {'type': ['string', 'null'], 'minLength': 1},
    }, ('id',))),
    'services': _array(_object({
        'name': _NAME, 'type': _NAME, 'description': _DESCRIPTION,
        'enabled': _ENABLED, 'endpoints': _array(_ENDPOINT),
    }, ('name', 'type'))),
    'domains': _array(_object({
        'name': _NAME, 'id': _NAME, 'description': _DESCRIPTION,
        'enabled': _ENABLED, 'config': _DOMAIN_CONFIG,
    }, ('name',))),
    'projects': _array(_object({
        'name': _NAME, 'domain': _NAME, 'description': _DESCRIPTION,
        'enabled': _ENABLED,
    }, ('name', 'domain'))),
    'users': _array(_object({
        'name': _NAME, 'domain': _NAME, 'description': _DESCRIPTION,
        'enabled': _ENABLED,
    }, ('name', 'domain'))),
    'groups': _array(_object({
        'name': _NAME, 'domain': _NAME, 'description': _DESCRIPTION,
    }, ('name', 'domain'))),
    'group_memberships': _array(_object({
        'user': _REFERENCE, 'group': _REFERENCE,
    }, ('user', 'group'))),
    'role_assignments': _array(_ASSIGNMENT),
})


class _Loader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in mapping:
                raise yaml.constructor.ConstructorError(
                    None, None, 'Expected unique string keys',
                    key_node.start_mark)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def ordered_regions(regions):
    """Order declared parents before children, including updates."""
    pending = {region['id']: region for region in regions}
    result = []
    while pending:
        ready = [region for region in pending.values()
                 if region.get('parent_region') not in pending]
        if not ready:
            raise BootstrapError('Cyclic parent_region references in regions')
        for region in ready:
            result.append(region)
            del pending[region['id']]
    return result


def _unique(items, fields, section):
    seen = set()
    for item in items:
        key = tuple(item[field] for field in fields)
        if key in seen:
            raise BootstrapError('Duplicate declaration in %s' % section)
        seen.add(key)


def validate_config(config):
    error = next(jsonschema.Draft4Validator(_SCHEMA).iter_errors(config), None)
    if error is not None:
        path = ('.'.join(str(part) for part in error.absolute_path)
                or 'document')
        # Validation errors may include the LDAP password in their instance
        # or message. Report only the location and the failed schema rule.
        raise BootstrapError('Invalid bootstrap configuration at %s (%s)' %
                             (path, error.validator))
    for section, fields in (
        ('roles', ('name',)), ('regions', ('id',)),
        ('services', ('name', 'type')), ('domains', ('name',)),
        ('projects', ('domain', 'name')), ('users', ('domain', 'name')),
        ('groups', ('domain', 'name')),
    ):
        _unique(config.get(section, []), fields, section)
    for service in config.get('services', []):
        _unique(service.get('endpoints', []), ('interface', 'region'),
                'service endpoints')
    ordered_regions(config.get('regions', []))


def load_config(path):
    try:
        with open(path, encoding='utf-8') as stream:
            config = yaml.load(stream, Loader=_Loader)
    except OSError as error:
        raise BootstrapError('Cannot read bootstrap file %s: %s' %
                             (path, error.strerror)) from None
    except (yaml.YAMLError, UnicodeError) as error:
        mark = getattr(error, 'problem_mark', None)
        location = (' at line %s, column %s' %
                    (mark.line + 1, mark.column + 1)) if mark else ''
        raise BootstrapError('Invalid bootstrap YAML%s' % location) from None
    validate_config(config)
    return config
