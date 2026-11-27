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

import time


class Score(object):
    def __init__(self, credit, refill_time, refill_amount):
        self.credit = credit
        self.refill_time = refill_time
        self.refill_amount = refill_amount
        self.value = self.credit
        self.last_update = time.time()

    def _refill_count(self):
        return int(((time.time() - self.last_update) / self.refill_time))

    def reset(self):
        self.value = self.credit
        self.last_update = time.time()

    def get(self):
        return min(
            self.credit,
            self.value + self._refill_count() * self.refill_amount
        )

    def reduce(self, consumption):
        refill_count = self._refill_count()
        self.value += refill_count * self.refill_amount
        self.last_update += refill_count * self.refill_time

        if self.value >= self.credit:
            self.reset()
        if consumption > self.value:
            self.value = 0
            return False

        self.value -= consumption
        return True
