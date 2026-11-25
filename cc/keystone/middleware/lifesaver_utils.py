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
from oslo_log import log

from . import score
from .lifesaver_logic import hash_token_id
from .lifesaver_logic import should_update_score_metadata

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
MAX_CAS_ATTEMPTS = 3


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
                        help='Credit consumption by status for users'), group=group)
        CONF.register_opt(
            cfg.DictOpt('token_cost', default=conf.get('token_cost', "default:1,401:10,403:5,404:10,429:0"),
                        help='Credit consumption by status for token and S3/EC2 credential validation'), group=group)

        self.enabled = CONF.lifesaver.enabled.lower() in ['true', '1', 't', 'y', 'yes']

        self.memcached = memcache.Client(
            servers=[x.strip() for x in CONF.lifesaver.memcached.split(',')],
            cache_cas=True, socket_timeout=0.1)

        self.domain_allowlist = [self.normalize(x) for x in CONF.lifesaver.domain_allowlist.split(',')]
        self.user_allowlist = [self.normalize(x) for x in CONF.lifesaver.user_allowlist.split(',')]
        self.user_blocklist = [self.normalize(x) for x in CONF.lifesaver.user_blocklist.split(',')]

        self.credit = CONF.lifesaver.initial_credit
        self.refill_time = CONF.lifesaver.refill_seconds
        self.refill_amount = CONF.lifesaver.refill_amount
        self.status_cost = CONF.lifesaver.status_cost
        self.token_cost = CONF.lifesaver.token_cost

    def get_memcache_key(self, user: bytes | str):
        if isinstance(user, bytes):
            user = user.decode("utf-8")
        return hashlib.md5(user.encode()).hexdigest()

    def get_score(self, user) -> score.Score:
        key = self.get_memcache_key(user)
        try:
            # Admission does not need a CAS token or a cache write.
            score_result = self.memcached.get(key)
        except Exception:
            LOG.debug('Lifesaver cache read failed; admitting request', exc_info=True)
            score_result = None
        if score_result is None or not isinstance(score_result, score.Score):
            score_result = score.Score(self.credit, self.refill_time, self.refill_amount)
        return score_result

    def deduct_credit(self, user, cost):
        """Charge a completed request using fresh, shared failure credit.

        Cache failures and sustained contention fail open. In-flight requests
        can finish after exhaustion; their responses must still be delivered.
        """
        key = self.get_memcache_key(user)
        expiration_time = self.credit * self.refill_time * self.refill_amount
        try:
            for _ in range(MAX_CAS_ATTEMPTS):
                cached = self.memcached.gets(key)
                current = cached
                if not isinstance(current, score.Score):
                    current = score.Score(self.credit, self.refill_time, self.refill_amount)
                current.reduce(cost)
                if should_update_score_metadata(
                        current, self.credit, self.refill_time, self.refill_amount):
                    current.credit = self.credit
                    current.refill_time = self.refill_time
                    current.refill_amount = self.refill_amount

                # add() prevents two initializers from overwriting each other.
                # A failed add/CAS always retries with a fresh score.
                if cached is None:
                    stored = self.memcached.add(key, current, expiration_time)
                else:
                    stored = self.memcached.cas(key, current, expiration_time)
                if stored:
                    return current
        except Exception:
            LOG.debug('Lifesaver cache update failed', exc_info=True)
        finally:
            # python-memcached keeps CAS tokens in a thread-local dictionary.
            # Retain them only for this bounded read/modify/write operation.
            self.memcached.reset_cas()
        return None

    def normalize(self, string=''):
        return string.strip().upper()

    def hash_token_id(self, token_id: str) -> str:
        return hash_token_id(
            token_id,
            secret_key=CONF.security_compliance.invalid_password_hash_secret_key,
            hash_function=CONF.security_compliance.invalid_password_hash_function,
        )
