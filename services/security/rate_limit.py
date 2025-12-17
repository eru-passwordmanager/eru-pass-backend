import time

_ATTEMPTS = {} # key -> [timestamps]
WINDOW = 60
MAX_ATTEMPTS = 5

def check_rate_limit(key: str):
    """
    Docstring for check_rate_limit
    
    :param key: Description
    :type key: str

    True -> pass
    False -> limit exceeded

    """