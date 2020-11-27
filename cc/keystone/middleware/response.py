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

import json
from webob import Response


class RateLimitExceededResponse(Response):
    """
    defines the rate limit response and defaults, which can be overwritten via configuration.
    """
    def __init__(self, status=None, headers=None, content_type=None, body=None, json_body=None):
        """
        creates a new RateLimitExceededResponse with either a body or json_body

        :param status: the status code
        :param headers: list of header dictionaries
        :param body: the response body
        :param json_body: the response json body
        """
        if not status:
            status = '429 Too Many Requests'

        if body:
            super(RateLimitExceededResponse, self).__init__(
                status=status, headerlist=headers, content_type=content_type, body=body, charset="UTF-8"
            )
            return
        elif not json_body:
            content_type = "application/json"
            json_body = {"error": {"status": status, "message": "Too Many Requests"}}
        super(RateLimitExceededResponse, self).__init__(
            status=status, headerlist=headers, content_type=content_type,
            json_body=json.dumps(json_body), charset="UTF-8",
        )

    def set_retry_after(self, retry_after):
        if not self.headerlist:
            self.headerlist = []
        self.headerlist.append(('Retry-After', str(retry_after)))


class BlocklistResponse(Response):
    """
    defines the blocklist response and defaults, which can be overwritten via configuration.
    """
    def __init__(self, status=None, headers=None, content_type=None, body=None, json_body=None):
        """
        creates a new BlocklistResponse with either a body or json_body

        :param status: the status code
        :param headers: list of header dictionaries
        :param body: the response body
        :param json_body: the response json body
        """
        if not status:
            status = '403 Forbidden'

        if body:
            super(BlocklistResponse, self).__init__(
                status=status, headerlist=headers, content_type=content_type, body=body, charset="UTF-8"
            )
            return
        elif not json_body:
            content_type = "application/json"
            json_body = {"error": {"status": status, "message": "You have been blocklisted"}}
        super(BlocklistResponse, self).__init__(
            status=status, headerlist=headers, content_type=content_type,
            json_body=json.dumps(json_body), charset="UTF-8"
        )
