from flask import request, jsonify
from functools import wraps
from config.security import RATE_LIMIT_WINDOW, RATE_LIMIT_MAX_REQUESTS
import time
import threading

# Global rate limit storage (persists across requests)
# In production, consider using Redis or memcached
_rate_limit_store = {}
_rate_limit_lock = threading.Lock()


def get_client_ip():
    """
    Get the client's IP address, considering proxy headers.
    Checks X-Forwarded-For and X-Real-IP headers for proxy scenarios.
    """
    # Check if behind proxy
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, get the first one (client)
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


def cleanup_expired_entries():
    """Remove expired entries from the rate limit store."""
    now = time.time()
    with _rate_limit_lock:
        expired_ips = []
        for ip, timestamps in _rate_limit_store.items():
            # Remove timestamps older than the window
            _rate_limit_store[ip] = [ts for ts in timestamps if ts > now - RATE_LIMIT_WINDOW]
            # Mark IP for removal if no recent requests
            if not _rate_limit_store[ip]:
                expired_ips.append(ip)

        # Remove IPs with no recent requests
        for ip in expired_ips:
            del _rate_limit_store[ip]


def rate_limit(func):
    """
    Rate limits a function based on IP address.

    Uses a sliding window algorithm to track requests.
    Stores data in memory (consider Redis for production).
    Proxy-aware IP detection.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip_address = get_client_ip()

        # Periodic cleanup of expired entries
        if len(_rate_limit_store) > 1000:  # Cleanup threshold
            cleanup_expired_entries()

        now = time.time()

        with _rate_limit_lock:
            # Initialize IP tracking if not exists
            if ip_address not in _rate_limit_store:
                _rate_limit_store[ip_address] = []

            # Remove timestamps outside the window
            _rate_limit_store[ip_address] = [
                ts for ts in _rate_limit_store[ip_address]
                if ts > now - RATE_LIMIT_WINDOW
            ]

            # Check if rate limit exceeded
            if len(_rate_limit_store[ip_address]) >= RATE_LIMIT_MAX_REQUESTS:
                time_to_wait = int(
                    RATE_LIMIT_WINDOW -
                    (now - _rate_limit_store[ip_address][0])
                )
                return jsonify({
                    'error': 'Too many requests',
                    'message': f'Rate limit exceeded. Please try again in {time_to_wait} seconds.',
                    'retry_after': time_to_wait
                }), 429

            # Add current timestamp
            _rate_limit_store[ip_address].append(now)

        return func(*args, **kwargs)

    return wrapper