import time
import threading

_FAIL_COUNT = 0
_LOCK = threading.Lock()

BASE_DELAY = 0.5 # seconds
MAX_DELAY = 4.0 # seconds

def record_failure_and_delay():
    """
    Docstring for record_failure_and_delay

    It is triggered when an incorrect unlock attempt occurs.
    It calculates delay and apply.
    """

    global _FAIL_COUNT

    with _LOCK:
        _FAIL_COUNT += 1
        delay = min(BASE_DELAY * (2**(_FAIL_COUNT -1)), MAX_DELAY)

    time.sleep(delay) # server side delay

def reset_failures():
    """
    Docstring for reset_failures
    It is triggered after unlock or manual lock.
    """
    global _FAIL_COUNT
    with _LOCK:
        _FAIL_COUNT = 0