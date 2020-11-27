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

import memcache
import hashlib

from keystone.common import wsgi
import keystone.conf
from oslo_log import log
from oslo_config import cfg
from . import response
from . import score

CONF = keystone.conf.CONF


class LifesaverMiddleware(wsgi.Middleware):
    def __init__(self, app, conf):
        super(LifesaverMiddleware, self).__init__(app)

        self.logger = log.getLogger(__name__)
        self.app = app

        group = cfg.OptGroup(name='lifesaver', title='Converged Cloud lifesaver middleware options')
        CONF.register_opt(cfg.StrOpt('enabled', default=conf.get('enabled', 'false'), help='Activate the lifesaver middleware'),group=group)
        CONF.register_opt(cfg.StrOpt('memcached', default=conf.get('memcached', '127.0.0.1'), help='The memcached host(s) to use'),group=group)
        CONF.register_opt(cfg.StrOpt('domain_allowlist', default=conf.get('domain_allowlist', 'Default'),help='Domains that are allowlisted'), group=group)
        CONF.register_opt(cfg.StrOpt('user_allowlist', default=conf.get('user_allowlist', 'keystone'),help='Users that are allowlisted'), group=group)
        CONF.register_opt(cfg.StrOpt('user_blocklist', default=conf.get('user_blocklist', ''), help='Users that are blocklisted'),group=group)
        CONF.register_opt(cfg.IntOpt('initial_credit', default=conf.get('initial_credit', 100), help='Initial user credit'), group=group)
        CONF.register_opt(cfg.IntOpt('refill_seconds', default=conf.get('refill_seconds', 60), help='Refill every n seconds'),group=group)
        CONF.register_opt(cfg.IntOpt('refill_amount', default=conf.get('refill_amount', 5), help='Refill amount per intervall'),group=group)
        CONF.register_opt(cfg.DictOpt('status_cost', default=conf.get('status_cost', "default:1,401:10,403:5,404:0,429:0"), help='Credit consumption by status'),group=group)

        self.enabled = CONF.lifesaver.enabled.lower() in ['true', '1', 't', 'y', 'yes']

        self.memcached = memcache.Client(servers=[x.strip() for x in CONF.lifesaver.memcached.split(',')], debug=1)
        self.domain_allowlist = [x.upper().strip() for x in CONF.lifesaver.domain_allowlist.split(',')]
        self.user_allowlist = [x.upper().strip() for x in CONF.lifesaver.user_allowlist.split(',')]
        self.user_blocklist = [x.upper().strip() for x in CONF.lifesaver.user_blocklist.split(',')]

        self.credit = CONF.lifesaver.initial_credit
        self.refill_time = CONF.lifesaver.refill_seconds
        self.refill_amount = CONF.lifesaver.refill_amount

        self.status_cost = CONF.lifesaver.status_cost

        # default responses
        self.ratelimit_response = response.RateLimitExceededResponse()
        self.ratelimit_response.set_retry_after(self.refill_time)
        self.blocklist_response = response.BlocklistResponse()

        if CONF.debug:
            self.logger.debug('enabled? {0}'.format(self.enabled))
            self.logger.debug('using memcached at {0}'.format(CONF.lifesaver.memcached))
            self.logger.debug('domain-allowlist is {0}'.format(self.domain_allowlist))
            self.logger.debug('user-allowlist is {0}'.format(self.user_allowlist))
            self.logger.debug('user-blocklist is {0}'.format(self.user_blocklist))
            self.logger.debug('initial-credit is {0}'.format(self.credit))
            self.logger.debug('refill-time is {0}'.format(self.refill_time))
            self.logger.debug('refill-amount is {0}'.format(self.refill_amount))
            self.logger.debug('status-costs are {0}'.format(self.status_cost))

    def get_user(self, request):
        """
        Tries to fetch user and its domain from the request
        :param request: the clients request
        :return: a dict with 'user' and 'domain'
        """

        # shortcut for version discovery request
        if '/v3/' == request.path:
            return None

        user = None
        domain = None

        try:
            # grab credentials from an authentication request
            if '/v3/auth/tokens' == request.path and 'POST' == request.method:
                body = request.json_body
                if 'auth' in body:
                    if 'identity' in body['auth']:
                        if 'password' in body['auth']['identity']:
                            if 'user' in body['auth']['identity']['password']:
                                user = body['auth']['identity']['password']['user'].get('name', None)
                                if not user:
                                    user = body['auth']['identity']['password']['user'].get('id', None)
                                    if user:
                                        user = 'id-' + user
                                if 'domain' in body['auth']['identity']['password']['user']:
                                    domain = body['auth']['identity']['password']['user']['domain'].get('name', None)
                                    if not domain:
                                        domain = body['auth']['identity']['password']['user']['domain'].get('id', None)
                        elif 'application_credential' in body['auth']['identity']:
                            user = body['auth']['identity']['application_credential'].get('id', None)
                            if user:
                                user = 'ac-' + user

            # grab credentials from an authenticated request
            if not user or not domain:
                context = request.context_dict

                if 'environment' in context:
                    # grab from request env
                    if not user:
                        user = context['environment'].get('HTTP_X_USER_NAME', None)
                    if not domain:
                        domain = context['environment'].get('HTTP_X_USER_DOMAIN_NAME', None)

                    # try token info
                    if not user or not domain:
                        # grab from token
                        token_info = context['environment'].get('keystone.token_info', None)
                        if token_info:
                            token = token_info.get('token', None)
                            if token:
                                user_info = token.get('user', None)
                                if user_info:
                                    user = user_info.get('name', None)
                                    domain_info = user_info.get('domain', None)
                                    if domain_info:
                                        domain = domain_info.get('name', None)
        except Exception as e:
            self.logger.error("Could not extract credentials from request: %s %s" % (request, e))

        if not user:
            user = ''
        if not domain:
            domain = ''

        return {'user': user.strip().upper(), 'domain': domain.strip().upper()}

    def process_request(self, request):
        return self.verify_request(request)

    def process_response(self, request, response):
        return self.verify_request(request, response)

    def verify_request(self, request, response=None):
        """
        Verifies if the request should be denied
        :param request:
        :param response:
        :return:
        """
        result = response

        # skip if not enabled
        if not self.enabled:
            return result

        # skip requests that have been processed already elsewhere in the middleware pipeline
        if 'lifesaver' in request.environ:
            return result

        credentials = self.get_user(request)
        if credentials:
            # request from allowlisted domain?
            domain = credentials['domain'].encode('utf8')
            if domain and domain in self.domain_allowlist:
                return result

            user = credentials['user'].encode('utf8')
            if user:
                # request from allowlisted user?
                if user in self.user_allowlist:
                    return result

                # request from blocklisted user?
                if user in self.user_blocklist:
                    self.logger.info("Request from blocklisted user %s rejected" % user)
                    return self.blocklist_response

                key = hashlib.md5(credentials['user'].encode()).hexdigest()

                user_score = self.memcached.gets(key)
                if not user_score:
                    user_score = score.Score(self.credit, self.refill_time, self.refill_amount)

                if user_score.get() == 0:
                    self.logger.info("Blocking request %s %s, since user %s %s has no credit left" % (request.method, request.path, credentials['user'], credentials['domain']))
                    return self.ratelimit_response

                if response:
                    status = response.status_code

                    # update user score?
                    if status >= 400:
                        # what penalty should be applied?
                        cost = self.status_cost['default']
                        if str(status) in self.status_cost:
                            cost = self.status_cost[str(status)]
                            # mark request as processed
                            request.environ['lifesaver'] = user

                        # deduct user credit ?
                        if int(cost) > 0:
                            user_score.reduce(int(cost))

                            # update score metadata in case the configuration has changed
                            if user_score.credit != self.credit:
                                user_score.credit = self.credit
                            if user_score.refill_time != self.refill_time:
                                user_score.refill_time = self.refill_time
                            if user_score.refill_amount != self.refill_amount:
                                user_score.refill_amount = self.refill_amount

                            self.memcached.set(key, user_score, self.credit * self.refill_time * self.refill_amount)
                            self.logger.info("User %s %s has a remaining credit of %d - request %s %s returned %d" % (credentials['user'], credentials['domain'], user_score.get(), request.method, request.path, status))

        return result

    @classmethod
    def factory(cls, global_config, **local_config):
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, conf)

        return _factory
