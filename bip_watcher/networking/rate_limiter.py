# networking/rate_limiter.py
import asyncio, time, random
from collections import defaultdict

class DomainRateLimiter:
    def __init__(self, min_delay=0.5, max_delay=1.5):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.last_request = {}
        self.locks = defaultdict(asyncio.Lock)
        self.problem_domains = defaultdict(int)

    async def wait(self, domain: str):
        async with self.locks[domain]:
            last = self.last_request.get(domain, 0)
            now = time.time()
            elapsed = now - last

            base_delay = self.min_delay
            if self.problem_domains.get(domain, 0) > 3:
                base_delay = 2.0

            delay = random.uniform(base_delay, base_delay * 2)
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)

            self.last_request[domain] = time.time()

    def report_403(self, domain: str):
        self.problem_domains[domain] += 1
