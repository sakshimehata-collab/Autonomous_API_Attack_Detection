"""
Member 4 - IP Blocker

Maintains a list of IP addresses that have been blocked
by the autonomous response engine.
"""

blocked_ips = set()


def block_ip(ip):
    """Block an IP address."""
    if not ip:
        return False

    blocked_ips.add(ip)
    return True


def unblock_ip(ip):
    """Remove an IP address from the blocked list."""
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        return True

    return False


def is_blocked(ip):
    """Check whether an IP address is currently blocked."""
    return ip in blocked_ips


def get_blocked_ips():
    """Return all currently blocked IP addresses."""
    return list(blocked_ips)