from flask import request, g
from functools import wraps
from config.security import RATE_LIMIT_WINDOW, RATE_LIMIT_MAX_REQUESTS
import time

def rate_limit(func):
    """Rate limits a function based on IP address."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip_address = request.remote_addr
        if not hasattr(g, 'rate_limits'):
            g.rate_limits = {}
        if ip_address not in g.rate_limits:
            g.rate_limits[ip_address] = []

        now = time.time()
        g.rate_limits[ip_address] = [ts for ts in g.rate_limits[ip_address] if ts > now - RATE_LIMIT_WINDOW]

        if len(g.rate_limits[ip_address]) >= RATE_LIMIT_MAX_REQUESTS:
            return "Too many requests. Please try again later.", 429  # HTTP 429 Too Many Requests

        g.rate_limits[ip_address].append(now)
        return func(*args, **kwargs)
    return wrapper