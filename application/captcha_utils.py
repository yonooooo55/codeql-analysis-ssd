import os, requests
from typing import Optional
VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"

def captcha_is_valid(token: str, remote_ip: Optional[str] = None) -> bool:
    # skip CAPTCHA in testing mode
    if os.getenv("TESTING") == "1":
        return True

    """
    Return True if Google says the token is good.
    """
    secret = os.getenv("RECAPTCHA_SECRET")
    if not (secret and token):
        return False

    data = {"secret": secret, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip

    try:
        r = requests.post(VERIFY_URL, data=data, timeout=5)
        result = r.json()
        return result.get("success", False)
    except requests.RequestException:
        return False