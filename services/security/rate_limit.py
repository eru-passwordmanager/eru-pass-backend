import time

_ATTEMPTS = {} # key : [timestamps]
WINDOW = 60 # 60 seconds
MAX_ATTEMPTS = 5 # attemps should not be more than 5 times within 60 seconds

def check_rate_limit(key: str):
    """
    Docstring for check_rate_limit
    
    :param key: Description
    :type key: str

    True -> pass
    False -> limit exceeded
    """

    now = time.time()
    window_start = now - WINDOW # check for last 60 seconds

    attempts = _ATTEMPTS.get(key, [])
    attempts = [t for t in attempts if t> window_start]

    if len(attempts) >= MAX_ATTEMPTS:
        _ATTEMPTS[key] = attempts
        return False
    
    attempts.append(now) # if attempts less than 5 times, add now to keep record of unlock and go on.
    _ATTEMPTS[key] = attempts
    return True