import math
from zxcvbn import zxcvbn

MIN_ENTROPY = 60.0

def estimate_entropy(password: str): # deprecated to use zxcvbn
    """
    Docstring for estimate_entropy
    
    :param password: Description
    :type password: str

    basic entropy estimation
    """

    if not password:
        return 0.0
    
    charset = 0

    if any(c.islower for c in password):
        charset += 26

    if any(c.issupper() for c in password):
        charset += 26

    if any(c.isdigit() for c in password):
        charset += 10
    
    if any(not c.isalnum() for c in password):
        charset += 32

    if charset == 0:
        return 0.0
    
    return math.log2(charset) * len(password)

def is_strong_master_password(password: str):
    entropy = estimate_entropy(password)
    return entropy >= MIN_ENTROPY, entropy

MIN_ZXCVBN_SCORE = 3 # 0 1 2 3 4

def check_master_password_strength(password: str):
    """
    Docstring for check_master_password_strength
    
    :param password: Description
    :type password: str

    real password strength check based on zxcvbn
    return:
    {
      ok: bool,
      score: int,
      guesses: int,
      crack_time_seconds: float,
      feedback: { warning, suggestions }
    }
    """

    if not password:
        return {
            "ok":False,
            "score":0,
            "feedback":{
                "warning":"Password is empty",
                "suggestions":[]
            }
        }
    
    result = zxcvbn(password)

    score = result["score"]
    ok = score >= MIN_ZXCVBN_SCORE

    return {
        "ok":ok,
        "score":score,
        "guesses": result["guesses"],
        "crack_time_seconds": result["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"],
        "feedback":result["feedback"]
    }