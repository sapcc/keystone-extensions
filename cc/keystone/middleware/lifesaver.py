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

from json.decoder import JSONDecodeError

import keystone.conf
from oslo_log import log
from oslo_middleware import base
from keystone.token.providers import fernet

from . import lifesaver_utils as utils
from . import lifesaver_logic as logic
from . import response

from webob import Request

CONF = keystone.conf.CONF


class LifesaverMiddleware(base.ConfigurableMiddleware):
    def __init__(self, app, conf):
        super(LifesaverMiddleware, self).__init__(app, conf)

        self.logger = log.getLogger(__name__)
        self.app = app
        self.utils = utils.LifesaverUtils(conf)
        self.fernet_provider = fernet.Provider()


        # default responses
        self.ratelimit_response = response.RateLimitExceededResponse()
        self.ratelimit_response.set_retry_after(self.utils.refill_time)
        self.blocklist_response = response.BlocklistResponse()

        if CONF.debug:
            self.logger.debug('enabled? {0}'.format(self.utils.enabled))
            self.logger.debug('using memcached at {0}'.format(self.utils.memcached))
            self.logger.debug('domain-allowlist is {0}'.format(self.utils.domain_allowlist))
            self.logger.debug('user-allowlist is {0}'.format(self.utils.user_allowlist))
            self.logger.debug('user-blocklist is {0}'.format(self.utils.user_blocklist))
            self.logger.debug('initial-credit is {0}'.format(self.utils.credit))
            self.logger.debug('refill-time is {0}'.format(self.utils.refill_time))
            self.logger.debug('refill-amount is {0}'.format(self.utils.refill_amount))
            self.logger.debug('status-costs are {0}'.format(self.utils.status_cost))

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
            user, domain = logic.extract_password_auth_credentials(request)
            if not user:
                user = logic.extract_app_credential(request)
            if not user:
                token_id = logic.extract_token_id(request)
                if token_id:
                    # use fernet provider to decode token and extract user id and domain
                    try:
                        (user_id, methods, audit_ids, system, domain, project_id,
                trust_id, federated_group_ids, identity_provider_id,
                protocol_id, access_token_id, app_cred_id, thumbprint,
                issued_at, expires_at) = self.fernet_provider.validate_token(token_id)
                        if user_id:
                            user = 'ftokencreds-' + user_id
                    except Exception as e:
                        self.logger.error("Could not validate token ...%s: %s" % (token_id[:8], str(e)))
            if not user:
                user, domain = logic.extract_s3_ec2_credentials(request)
            if not user:
                user, domain = logic.extract_from_authentication_request(request)
        except Exception as e:
            self.logger.error("Could not extract credentials from request: %s %s %s" % (
                request.method, request.path, e))

        if not user:
            user = ''
        if not domain:
            domain = ''

        return {'user': self.utils.normalize(user), 'domain': self.utils.normalize(domain)} 

    def process_request(self, request):
        return self.verify_request(request)

    def process_response(self, response, request=None):
        return self.verify_request(request, response)

    def get_costs(self, request, response, item, item_score):
        status = response.status_code
        cost = 0
        # determine cost based on response status
        if status >= 400:
            # check prefix to decide which cost table to use
            if item.startswith("FTOKENCREDS-"):
                cost = self.utils.token_cost['default']
                if str(status) in self.utils.token_cost:
                    cost = self.utils.token_cost[str(status)]
            else:
                cost = self.utils.status_cost['default']
                if str(status) in self.utils.status_cost:
                    cost = self.utils.status_cost[str(status)]

        # deduct user credit ?
        if int(cost) > 0:
            # mark request as processed
            request.environ['lifesaver'] = item
            item_score.reduce(int(cost))
            # update score metadata in case the configuration has changed
            if item_score.credit != self.utils.credit:
                item_score.credit = self.utils.credit
            if item_score.refill_time != self.utils.refill_time:
                item_score.refill_time = self.utils.refill_time
            if item_score.refill_amount != self.utils.refill_amount:
                item_score.refill_amount = self.utils.refill_amount

            self.utils.set_score(item, item_score)
            self.logger.info("%s has a remaining credit of %d - request %s %s returned %d" % (
            item, item_score.get(), request.method, request.path,
            status))


    def verify_request(self, request, response=None):
        """
        Verifies if the request should be denied
        :param request:
        :param response:
        :return:
        """
        result = response

        if not self.utils.enabled:
            return result

        # skip requests that have been processed already elsewhere in the middleware pipeline
        if 'lifesaver' in request.environ:
            return result

        credentials = self.get_user(request)
        if credentials:
            domain = credentials['domain']
            if domain and credentials['domain'] in self.utils.domain_allowlist:
                return result

            user = credentials['user']
            if user:
                # request from allowlisted user?
                if credentials['user'] in self.utils.user_allowlist:
                    return result

                # request from blocklisted user?
                if credentials['user'] in self.utils.user_blocklist:
                    self.logger.info("Request from blocklisted user %s rejected" % user)
                    return self.blocklist_response

                user_score = self.utils.get_score(credentials['user'])

                if user_score.get() == 0:
                    self.logger.info("Blocking request %s %s, since user %s %s has no credit left" % (
                    request.method, request.path, user, domain))
                    return self.ratelimit_response

                if response:
                    self.logger.info("Response exists, calling calculate_score")
                    self.get_costs(request, response, user, user_score)
                else:
                    self.logger.info("No response, skipping calculate_score")

        return result

    @classmethod
    def factory(cls, global_config, **local_config):
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, conf)

        return _factory
