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

import keystone.conf
from oslo_log import log
from oslo_middleware import base
from . import lifesaver_utils as utils
from . import response

CONF = keystone.conf.CONF


class LifesaverMiddleware(base.ConfigurableMiddleware):
    def __init__(self, app, conf):
        super(LifesaverMiddleware, self).__init__(app, conf)

        self.logger = log.getLogger(__name__)
        self.app = app
        self.utils = utils.LifesaverUtils(conf)

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

            elif (('/v3/s3tokens' == request.path or
                   '/v3/ec2tokens' == request.path) and
                  'POST' == request.method):
                # s3tokens/ec2tokens never contains user id, so use
                # credential's `access` field to identify it
                body = request.json_body
                # the order is taken from EC2_S3_Resource.py in keystone
                credentials = (
                    body.get('credentials') or
                    body.get('credential') or
                    body.get('ec2Credentials')
                )
                if '/v3/s3tokens' == request.path:
                    prefix = 's3creds'
                elif '/v3/ec2tokens' == request.path:
                    prefix = 'ec2creds'
                if credentials:
                    try:
                        user = prefix + '-' + credentials['access']
                        # ec2tokens and s3tokens API are domain unaware. Lets
                        # just log it.
                        domain = 'unknown'
                        # the message will look like this:
                        # Blocking request POST /v3/s3tokens, since user \
                        # b's3creds-123456' b'unknown' has no credit left
                        # OR 'b'ec2creds-123456 b'unknown' has no credit left
                    except KeyError:
                        pass


            # grab credentials from an authenticated request
            if not user or not domain:
                context = request.environ

                if 'KEYSTONE_AUTH_CONTEXT' in context:
                    # grab from request env
                    if not user:
                        user = context.get('HTTP_X_USER_NAME', None)
                    if not domain:
                        domain = context.get('HTTP_X_USER_DOMAIN_NAME', None)

                    # try token info
                    if not user or not domain:
                        # grab from token
                        token_info = context.get('keystone.token_info', None)
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

        return {'user': self.utils.normalize(user), 'domain': self.utils.normalize(domain)}

    def process_request(self, request):
        return self.verify_request(request)

    def process_response(self, response, request=None):
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
        if not self.utils.enabled:
            return result

        # skip requests that have been processed already elsewhere in the middleware pipeline
        if 'lifesaver' in request.environ:
            return result

        credentials = self.get_user(request)
        if credentials:
            # request from allowlisted domain?
            domain = credentials['domain'].encode('utf8')
            if domain and credentials['domain'] in self.utils.domain_allowlist:
                return result

            user = credentials['user'].encode('utf8')
            if user:
                # request from allowlisted user?
                if credentials['user'] in self.utils.user_allowlist:
                    return result

                # request from blocklisted user?
                if credentials['user'] in self.utils.user_blocklist:
                    self.logger.info("Request from blocklisted user %s rejected" % user)
                    return self.blocklist_response

                user_score = self.utils.get_user_score(credentials['user'])

                if user_score.get() == 0:
                    self.logger.info("Blocking request %s %s, since user %s %s has no credit left" % (
                    request.method, request.path, user, domain))
                    return self.ratelimit_response

                if response:
                    status = response.status_code

                    # update user score?
                    if status >= 400:
                        # what penalty should be applied?
                        cost = self.utils.status_cost['default']
                        if str(status) in self.utils.status_cost:
                            cost = self.utils.status_cost[str(status)]
                            # mark request as processed
                            request.environ['lifesaver'] = user

                        # deduct user credit ?
                        if int(cost) > 0:
                            user_score.reduce(int(cost))

                            # update score metadata in case the configuration has changed
                            if user_score.credit != self.utils.credit:
                                user_score.credit = self.utils.credit
                            if user_score.refill_time != self.utils.refill_time:
                                user_score.refill_time = self.utils.refill_time
                            if user_score.refill_amount != self.utils.refill_amount:
                                user_score.refill_amount = self.utils.refill_amount

                            self.utils.set_user_score(credentials['user'], user_score)
                            self.logger.info("User %s %s has a remaining credit of %d - request %s %s returned %d" % (
                            user, domain, user_score.get(), request.method, request.path,
                            status))

        return result

    @classmethod
    def factory(cls, global_config, **local_config):
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, conf)

        return _factory
