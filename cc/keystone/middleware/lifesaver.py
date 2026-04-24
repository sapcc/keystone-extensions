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

from . import lifesaver_logic as logic
from . import lifesaver_utils as utils
from . import response
from .lifesaver_logic import calculate_cost
from .lifesaver_logic import FTOKENCREDS_PREFIX
from .lifesaver_logic import should_update_score_metadata
from cc.keystone.middleware import score

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
            self.logger.debug('token-costs are {0}'.format(self.utils.token_cost))

    def get_subject(self, request):
        """
        Tries to fetch the rate-limit subject and its domain from the request.
        The subject can be a user, token, or credential identifier.
        :param request: the clients request
        :return: a dict with 'subject' and 'domain'
        """

        # shortcut for version discovery request
        if '/v3/' == request.path:
            return None

        subject = None
        domain = None

        try:
            subject, domain = logic.extract_password_auth_credentials(request)
            if not subject:
                subject = logic.extract_app_credential(request)
            if not subject:
                token_id = logic.extract_token_id(request)
                if token_id:
                    token_hash = self.utils.hash_token_id(token_id)
                    subject = FTOKENCREDS_PREFIX + token_hash
            if not subject:
                subject, domain = logic.extract_s3_ec2_credentials(request)
            if not subject:
                subject, domain = logic.extract_from_authentication_request(request)
        except Exception as e:
            self.logger.error("Could not extract credentials from request: %s %s %s" % (
                request.method, request.path, e))

        if not subject:
            subject = ''
        if not domain:
            domain = ''

        return {'subject': self.utils.normalize(subject), 'domain': self.utils.normalize(domain)}

    def process_request(self, request):
        return self.verify_request(request)

    def process_response(self, response, request=None):
        return self.verify_request(request, response)

    def get_costs(self, request, response, subject, subject_score):
        cost = calculate_cost(
            response.status_code,
            subject,
            self.utils.status_cost,
            self.utils.token_cost
        )

        # deduct subject credit
        if cost > 0:
            # mark request as processed
            request.environ['lifesaver'] = subject
            subject_score.reduce(cost)
            # update score metadata in case the configuration has changed
            if should_update_score_metadata(
                subject_score,
                self.utils.credit,
                self.utils.refill_time,
                self.utils.refill_amount
            ):
                subject_score.credit = self.utils.credit
                subject_score.refill_time = self.utils.refill_time
                subject_score.refill_amount = self.utils.refill_amount

            self.utils.set_score(subject, subject_score)
            self.logger.info("%s has a remaining credit of %d - request %s %s returned %d" % (
                subject, subject_score.get(), request.method, request.path,
                response.status_code))

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

        credentials = self.get_subject(request)
        if credentials:
            domain = credentials['domain']
            if domain and credentials['domain'] in self.utils.domain_allowlist:
                return result

            subject = credentials['subject']
            if subject:
                # request from allowlisted subject?
                if credentials['subject'] in self.utils.user_allowlist:
                    return result

                # request from blocklisted subject?
                if credentials['subject'] in self.utils.user_blocklist:
                    self.logger.info("Request from blocklisted subject %s rejected" % subject)
                    return self.blocklist_response

                subject_score: score.Score = self.utils.get_score(credentials['subject'])

                if subject_score.get() <= 0:
                    self.logger.info("Blocking request %s %s, since subject %s %s has no credit left" % (
                    request.method, request.path, subject[:30], domain))
                    return self.ratelimit_response

                if response:
                    self.get_costs(request, response, subject, subject_score)

        return result

    @classmethod
    def factory(cls, global_config, **local_config):
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, conf)

        return _factory
