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


from datadog.dogstatsd import DogStatsd
import keystone.conf
from oslo_log import log
from oslo_middleware import base

from . import lifesaver_logic as logic
from . import lifesaver_utils as utils
from . import response
from .lifesaver_logic import calculate_cost
from .lifesaver_logic import FTOKENCREDS_PREFIX

CONF = keystone.conf.CONF
REQUEST_STATE = 'lifesaver.state'


class LifesaverMiddleware(base.ConfigurableMiddleware):
    def __init__(self, app, conf):
        super(LifesaverMiddleware, self).__init__(app, conf)

        self.logger = log.getLogger(__name__)
        self.app = app
        self.utils = utils.LifesaverUtils(conf)
        self.phase = conf.get('phase', 'post_auth')
        if self.phase == 'pre_auth':
            # Use the same local StatsD exporter as Watcher. Early rejections
            # never reach Watcher and have no authenticated identity labels.
            self.metric_client = DogStatsd(
                host=conf.get('statsd_host', '127.0.0.1'),
                port=int(conf.get('statsd_port', 9125)),
                namespace='openstack_lifesaver')

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
            if self.phase == 'pre_auth':
                subject, domain = logic.extract_s3_ec2_credentials(request)
            else:
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
            self.logger.debug("Could not extract credentials from request: %s %s %s",
                              request.method, request.path, e)

        if not subject:
            subject = ''
        if not domain:
            domain = ''

        return {'subject': self.utils.normalize(subject), 'domain': self.utils.normalize(domain)}

    def process_request(self, request):
        if not self.utils.enabled:
            return None

        # An early owner accounts even for responses returned by AuthContext.
        # Keep ownership separate from the legacy positive-charge marker.
        if REQUEST_STATE in request.environ or 'lifesaver' in request.environ:
            return None
        credentials = self.get_subject(request)
        if not credentials or not credentials['subject']:
            return None

        state = dict(credentials, owner=self, accounted=False)
        request.environ[REQUEST_STATE] = state
        subject, domain = state['subject'], state['domain']
        if (domain and domain in self.utils.domain_allowlist or
                subject in self.utils.user_allowlist):
            state['accounted'] = True
            return None

        if subject in self.utils.user_blocklist:
            state['accounted'] = True
            self.logger.debug("Request from blocklisted subject %s rejected", subject)
            self.record_early_rejection(request, 'blocklist')
            return response.BlocklistResponse(headers=[('Vary', 'X-Auth-Token')])

        subject_score = self.utils.get_score(subject)
        if subject_score.get() <= 0:
            state['accounted'] = True
            self.logger.debug("Blocking request %s %s: subject %s %s has no credit",
                              request.method, request.path, subject, domain)
            self.record_early_rejection(request, 'credit')
            # Early responses also bypass AuthContext's response headers.
            result = response.RateLimitExceededResponse(
                headers=[('Vary', 'X-Auth-Token')])
            result.set_retry_after(subject_score.retry_after())
            return result
        return None

    def process_response(self, response, request=None):
        if request is None:
            return response
        state = request.environ.get(REQUEST_STATE)
        if not state or state['owner'] is not self or state['accounted']:
            return response

        state['accounted'] = True
        cost = calculate_cost(
            response.status_code,
            state['subject'],
            self.utils.status_cost,
            self.utils.token_cost
        )
        if cost > 0:
            subject = state['subject']
            request.environ['lifesaver'] = subject
            remaining = self.utils.deduct_credit(subject, cost)
            if remaining is not None:
                self.logger.debug("%s %s has credit %d after %s %s returned %d",
                                  subject, state['domain'], remaining.get(),
                                  request.method, request.path, response.status_code)
        # Admission is final: never replace a downstream response with a 429.
        return response

    def record_early_rejection(self, request, reason):
        if self.phase != 'pre_auth':
            return
        try:
            self.metric_client.increment(
                'early_rejections_total',
                tags=['endpoint:' + request.path.rsplit('/', 1)[-1],
                      'reason:' + reason])
        except Exception:
            self.logger.debug('Could not submit Lifesaver metric', exc_info=True)

    @classmethod
    def factory(cls, global_config, **local_config):
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, conf)

        return _factory
