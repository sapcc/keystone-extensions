import time


class Score(object):
    def __init__(self, credit, refill_time, refill_amount):
        self.credit = credit
        self.refill_time = refill_time
        self.refill_amount = refill_amount
        self.reset()

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
