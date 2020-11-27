# Copyright 2020 SAP SE
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

import hashlib
import keystone.conf
import memcache

from oslo_config import cfg

from . import score

CONF = keystone.conf.CONF

class LifesaverUtils(object):
    def __init__(self, conf):
        group = cfg.OptGroup(name='lifesaver', title='Converged Cloud lifesaver middleware options')
        CONF.register_opt(
            cfg.StrOpt('enabled', default=conf.get('enabled', 'false'), help='Activate the lifesaver middleware'),
            group=group)
        CONF.register_opt(
            cfg.StrOpt('memcached', default=conf.get('memcached', '127.0.0.1'), help='The memcached host(s) to use'),
            group=group)
        CONF.register_opt(cfg.StrOpt('domain_allowlist', default=conf.get('domain_allowlist', 'Default'),
                                     help='Domains that are allowlisted'), group=group)
        CONF.register_opt(cfg.StrOpt('user_allowlist', default=conf.get('user_allowlist', 'keystone'),
                                     help='Users that are allowlisted'), group=group)
        CONF.register_opt(
            cfg.StrOpt('user_blocklist', default=conf.get('user_blocklist', ''), help='Users that are blocklisted'),
            group=group)
        CONF.register_opt(
            cfg.IntOpt('initial_credit', default=conf.get('initial_credit', 100), help='Initial user credit'),
            group=group)
        CONF.register_opt(
            cfg.IntOpt('refill_seconds', default=conf.get('refill_seconds', 60), help='Refill every n seconds'),
            group=group)
        CONF.register_opt(
            cfg.IntOpt('refill_amount', default=conf.get('refill_amount', 5), help='Refill amount per intervall'),
            group=group)
        CONF.register_opt(
            cfg.DictOpt('status_cost', default=conf.get('status_cost', "default:1,401:10,403:5,404:0,429:0"),
                        help='Credit consumption by status'), group=group)

        self.enabled = CONF.lifesaver.enabled.lower() in ['true', '1', 't', 'y', 'yes']

        self.memcached = memcache.Client(servers=[x.strip() for x in CONF.lifesaver.memcached.split(',')], debug=1)

        self.domain_allowlist = [self.normalize(x) for x in CONF.lifesaver.domain_allowlist.split(',')]
        self.user_allowlist = [self.normalize(x) for x in CONF.lifesaver.user_allowlist.split(',')]
        self.user_blocklist = [self.normalize(x) for x in CONF.lifesaver.user_blocklist.split(',')]

        self.credit = CONF.lifesaver.initial_credit
        self.refill_time = CONF.lifesaver.refill_seconds
        self.refill_amount = CONF.lifesaver.refill_amount
        self.status_cost = CONF.lifesaver.status_cost

    def get_memcache_key(self, user):
        return hashlib.md5(user.encode()).hexdigest()

    def get_user_score(self, user):
        key = self.get_memcache_key(user)
        user_score = self.memcached.gets(key)
        if not user_score:
            user_score = score.Score(self.credit, self.refill_time, self.refill_amount)
        return user_score

    def set_user_score(self, user, user_score):
        key = self.get_memcache_key(user)
        expiration_time = self.credit * self.refill_time * self.refill_amount
        self.memcached.set(key, user_score, expiration_time)

    def normalize(self, string=''):
        return string.strip().upper()
