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

import copy
import unittest
from unittest import mock

from oslo_config import cfg
import webob

from cc.keystone.middleware import lifesaver
from cc.keystone.middleware import lifesaver_utils
from cc.keystone.middleware import response
from cc.keystone.middleware import score


class MemoryCache:
    """Copy cached values and simulate two requests updating the same key."""

    def __init__(self, store):
        self.store = store
        self.cas_ids = {}
        self.calls = []
        self.after_read = None

    def _read(self, key, cas=False):
        item = self.store.get(key)
        value = copy.deepcopy(item[1]) if item else None
        if cas and item:
            self.cas_ids[key] = item[0]
        callback, self.after_read = self.after_read, None
        if callback:
            callback()
        return value

    def get(self, key):
        self.calls.append('get')
        return self._read(key)

    def gets(self, key):
        self.calls.append('gets')
        return self._read(key, cas=True)

    def _write(self, key, value):
        revision = self.store.get(key, (0, None))[0] + 1
        self.store[key] = (revision, copy.deepcopy(value))
        return True

    def set(self, key, value, time=0):
        self.calls.append('set')
        return self._write(key, value)

    def add(self, key, value, time=0):
        self.calls.append('add')
        if key in self.store:
            return False
        return self._write(key, value)

    def cas(self, key, value, time=0):
        self.calls.append('cas')
        if key not in self.store:
            return False
        if self.store[key][0] != self.cas_ids.get(key):
            return False
        return self._write(key, value)

    def reset_cas(self):
        self.cas_ids.clear()


class LifesaverTestCase(unittest.TestCase):
    subject = 'S3CREDS-TEST-KEY'

    def setUp(self):
        super().setUp()
        self.store = {}
        self.conf = cfg.ConfigOpts()
        self.conf.register_opt(cfg.BoolOpt('debug', default=False))
        for module in (lifesaver, lifesaver_utils):
            patcher = mock.patch.object(module, 'CONF', self.conf)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(
            lifesaver_utils.memcache, 'Client',
            side_effect=lambda **kwargs: MemoryCache(self.store))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(lifesaver, 'DogStatsd')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.clock = mock.patch.object(score.time, 'time', return_value=100.)
        self.now = self.clock.start()
        self.addCleanup(self.clock.stop)
        # Register options before changing their values, as Keystone does.
        lifesaver_utils.LifesaverUtils({})
        for name, value in {
            'enabled': 'true', 'initial_credit': 100, 'refill_seconds': 10,
            'refill_amount': 5, 'domain_allowlist': '', 'user_allowlist': '',
        }.items():
            self.conf.set_override(name, value, group='lifesaver')
        self.middleware = self.make_middleware()

    def make_middleware(self, app=None, phase='post_auth'):
        if app is None:
            app = webob.Response(status=404, json_body={'missing': True})
        return lifesaver.LifesaverMiddleware.factory({}, phase=phase)(app)

    def request(self, endpoint='s3tokens', **kwargs):
        return webob.Request.blank(
            '/v3/' + endpoint, method='POST',
            json_body={'credentials': {'access': 'test-key'}}, **kwargs)

    def seed(self, value, subject=None):
        subject = subject or self.subject
        state = score.Score(100, 10, 5)
        state.reduce(100 - value)
        key = self.middleware.utils.get_memcache_key(subject)
        self.store[key] = (1, state)

    def balance(self, subject=None):
        key = self.middleware.utils.get_memcache_key(subject or self.subject)
        return self.store[key][1].get()

    def test_missing_credential_failure_consumes_credit(self):
        for endpoint in ('s3tokens', 'ec2tokens'):
            with self.subTest(endpoint=endpoint):
                result = self.request(endpoint).get_response(self.middleware)
                self.assertEqual(404, result.status_int)
                subject = ('S3' if endpoint == 's3tokens' else 'EC2')
                self.assertEqual(90, self.balance(subject + 'CREDS-TEST-KEY'))

    def test_legacy_loader_retains_authenticated_filtering(self):
        middleware = lifesaver.LifesaverMiddleware.factory({})(
            webob.Response(status=403))
        request = webob.Request.blank('/v3/projects', environ={
            'KEYSTONE_AUTH_CONTEXT': {},
            'HTTP_X_USER_NAME': 'ordinary-user',
            'HTTP_X_USER_DOMAIN_NAME': 'ordinary-domain',
        })
        self.assertEqual(403, request.get_response(middleware).status_int)
        self.assertEqual(95, self.balance('ORDINARY-USER'))

    def test_admitted_response_survives_concurrent_exhaustion(self):
        for status in (200, 201, 401, 404):
            with self.subTest(status=status):
                self.seed(100)
                request = self.request()
                self.assertIsNone(self.middleware.process_request(request))
                self.seed(0)
                original = webob.Response(
                    status=status, body=b'original response',
                    headers={'X-Subject-Token': 'issued-token'})
                result = self.middleware.process_response(original, request)
                self.assertIs(original, result)
                self.assertEqual(status, result.status_int)
                self.assertEqual(b'original response', result.body)
                self.assertEqual('issued-token', result.headers['X-Subject-Token'])

    def test_successful_response_needs_no_accounting_cache_access(self):
        request = self.request()
        self.middleware.process_request(request)
        cache = self.middleware.utils.memcached
        cache.calls.clear()
        original = webob.Response(status=200)
        self.assertIs(original, self.middleware.process_response(original, request))
        self.assertEqual([], cache.calls)

    def test_zero_cost_response_is_not_charged(self):
        request = self.request()
        self.middleware.process_request(request)
        cache = self.middleware.utils.memcached
        cache.calls.clear()
        self.middleware.process_response(webob.Response(status=429), request)
        self.assertEqual([], cache.calls)
        self.assertEqual({}, self.store)

    def test_concurrent_failures_both_deduct(self):
        self.seed(100)
        self._competing_failures()

    def test_concurrent_initialization_preserves_both_deductions(self):
        self._competing_failures()

    def _competing_failures(self):
        other = self.make_middleware()
        first_request, second_request = self.request(), self.request()
        self.middleware.process_request(first_request)
        other.process_request(second_request)
        failure = webob.Response(status=401)
        self.middleware.utils.memcached.after_read = (
            lambda: other.process_response(failure, second_request))
        self.middleware.process_response(failure, first_request)
        self.assertEqual(80, self.balance())

    def test_response_accounting_runs_only_once(self):
        request = self.request()
        self.middleware.process_request(request)
        failure = webob.Response(status=401)
        self.middleware.process_response(failure, request)
        self.middleware.process_response(failure, request)
        self.assertEqual(90, self.balance())

    def test_early_owner_skips_late_admission_and_accounting(self):
        downstream = mock.Mock(wraps=self.middleware)
        early = self.make_middleware(downstream, phase='pre_auth')
        extract = lifesaver.logic.extract_s3_ec2_credentials
        with mock.patch.object(lifesaver.logic, 'extract_s3_ec2_credentials',
                               wraps=extract) as extraction:
            result = self.request().get_response(early)
        self.assertEqual(404, result.status_int)
        self.assertEqual(90, self.balance())
        self.assertEqual(1, extraction.call_count)
        self.assertEqual([], self.middleware.utils.memcached.calls)
        downstream.assert_called_once()

    def test_early_rejection_avoids_downstream_and_uses_one_read(self):
        self.seed(0)
        downstream = mock.Mock(wraps=self.middleware)
        early = self.make_middleware(downstream, phase='pre_auth')
        for _ in range(3):
            result = self.request().get_response(early)
            self.assertEqual(429, result.status_int)
        downstream.assert_not_called()
        self.assertEqual(3, len(early.utils.memcached.calls))
        self.assertEqual(0, self.balance())

    def test_early_rejections_emit_low_cardinality_metrics(self):
        self.seed(0)
        with mock.patch.object(lifesaver, 'DogStatsd', create=True) as metrics:
            early = self.make_middleware(phase='pre_auth')
            self.assertEqual(429, self.request().get_response(early).status_int)
        metrics.return_value.increment.assert_called_once_with(
            'early_rejections_total',
            tags=['endpoint:s3tokens', 'reason:credit'])

    def test_metric_failure_preserves_early_rejection(self):
        self.seed(0)
        downstream = mock.Mock()
        early = self.make_middleware(downstream, phase='pre_auth')
        early.metric_client.increment.side_effect = OSError('unavailable')
        result = self.request().get_response(early)
        self.assertEqual(429, result.status_int)
        self.assertEqual(429, result.json['error']['code'])
        self.assertEqual('10', result.headers['Retry-After'])
        downstream.assert_not_called()

    def test_early_phase_ignores_authenticated_identity(self):
        self.seed(0, 'SCRIPT-USER')
        early = self.make_middleware(phase='pre_auth')
        request = webob.Request.blank('/v3/projects', environ={
            'KEYSTONE_AUTH_CONTEXT': {},
            'HTTP_X_USER_NAME': 'script-user',
            'HTTP_X_USER_DOMAIN_NAME': 'script-domain',
        })
        result = request.get_response(early)
        self.assertEqual(404, result.status_int)
        self.assertEqual([], early.utils.memcached.calls)

    def test_late_phase_retains_authenticated_identity_accounting(self):
        request = webob.Request.blank('/v3/projects', environ={
            'KEYSTONE_AUTH_CONTEXT': {},
            'HTTP_X_USER_NAME': 'script-user',
            'HTTP_X_USER_DOMAIN_NAME': 'script-domain',
        })
        late = self.make_middleware(webob.Response(status=403))
        early = self.make_middleware(late, phase='pre_auth')
        self.assertEqual(403, request.get_response(early).status_int)
        self.assertEqual(95, self.balance('SCRIPT-USER'))
        self.assertEqual([], early.utils.memcached.calls)

    def test_authentication_failure_is_accounted_by_early_phase(self):
        early = self.make_middleware(webob.Response(status=401), phase='pre_auth')
        self.assertEqual(401, self.request().get_response(early).status_int)
        self.assertEqual(90, self.balance())

    def test_disabled_and_allowlisted_requests_bypass_both_phases(self):
        for option, value in (('enabled', 'false'),
                              ('user_allowlist', self.subject),
                              ('domain_allowlist', 'unknown')):
            with self.subTest(option=option):
                self.conf.set_override(option, value, group='lifesaver')
                late = self.make_middleware()
                early = self.make_middleware(late, phase='pre_auth')
                self.seed(0)
                self.assertEqual(404, self.request().get_response(early).status_int)
                self.assertEqual([], early.utils.memcached.calls)
                self.assertEqual([], late.utils.memcached.calls)
                self.conf.set_override(
                    option, 'true' if option == 'enabled' else '', group='lifesaver')

    def test_blocklisted_request_does_not_reach_downstream(self):
        self.conf.set_override('user_blocklist', self.subject, group='lifesaver')
        downstream = mock.Mock()
        early = self.make_middleware(downstream, phase='pre_auth')
        result = self.request().get_response(early)
        self.assertEqual(403, result.status_int)
        self.assertIsInstance(result.json, dict)
        downstream.assert_not_called()

    def test_body_remains_readable_downstream(self):
        @webob.dec.wsgify
        def app(request):
            return webob.Response(json_body=request.json_body)
        early = self.make_middleware(self.make_middleware(app), phase='pre_auth')
        request = self.request()
        expected = request.json_body
        self.assertEqual(expected, request.get_response(early).json)

    def test_malformed_json_passes_through_early_phase(self):
        early = self.make_middleware(webob.Response(status=400), phase='pre_auth')
        request = webob.Request.blank(
            '/v3/s3tokens', method='POST', body=b'{invalid',
            content_type='application/json')
        self.assertEqual(400, request.get_response(early).status_int)
        self.assertEqual([], early.utils.memcached.calls)

    def test_retry_after_tracks_next_refill_without_extending_it(self):
        self.seed(0)
        self.now.return_value = 108.2
        result = self.request().get_response(self.middleware)
        self.assertEqual(429, result.status_int)
        self.assertEqual('2', result.headers['Retry-After'])
        self.now.return_value = 109.1
        result = self.request().get_response(self.middleware)
        self.assertEqual('1', result.headers['Retry-After'])
        self.now.return_value = 110.
        self.assertEqual(404, self.request().get_response(self.middleware).status_int)

    def test_expired_score_starts_with_initial_credit(self):
        self.seed(0)
        self.store.clear()  # Simulate a cache entry that has expired.
        self.assertEqual(404, self.request().get_response(self.middleware).status_int)

    def test_cache_read_errors_fail_open(self):
        cache = self.middleware.utils.memcached
        with mock.patch.object(cache, 'get', side_effect=OSError('unavailable')), \
                mock.patch.object(cache, 'gets', side_effect=OSError('unavailable')):
            self.assertEqual(404, self.request().get_response(self.middleware).status_int)

    def test_cache_write_errors_preserve_response(self):
        cache = self.middleware.utils.memcached
        request = self.request()
        self.middleware.process_request(request)
        failure = webob.Response(status=401, body=b'original')
        with mock.patch.object(cache, 'add', side_effect=OSError('unavailable')), \
                mock.patch.object(cache, 'set', side_effect=OSError('unavailable')):
            self.assertIs(failure, self.middleware.process_response(failure, request))

    def test_cache_write_failure_is_bounded(self):
        self.seed(100)
        cache = self.middleware.utils.memcached
        request = self.request()
        self.middleware.process_request(request)
        failure = webob.Response(status=401)
        with mock.patch.object(cache, 'cas', return_value=False) as cas:
            self.assertIs(failure, self.middleware.process_response(failure, request))
        self.assertGreater(cas.call_count, 0)
        self.assertLessEqual(cas.call_count, 3)
        self.assertEqual(100, self.balance())


class ResponseTests(unittest.TestCase):
    def test_error_bodies_are_json_objects(self):
        for response_type in (response.RateLimitExceededResponse,
                              response.BlocklistResponse):
            with self.subTest(response_type=response_type):
                result = response_type(headers=[('Vary', 'X-Auth-Token')])
                self.assertIsInstance(result.json, dict)
                self.assertIn('error', result.json)
                self.assertEqual(result.status_int, result.json['error']['code'])
                self.assertEqual('application/json', result.content_type)

    def test_setting_retry_after_replaces_header(self):
        result = response.RateLimitExceededResponse()
        result.set_retry_after(10)
        result.set_retry_after(2)
        self.assertEqual(['2'], result.headers.getall('Retry-After'))
