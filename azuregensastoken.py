# This code must run in Python Version 2
from base64 import b64encode, b64decode
from hashlib import sha256
from time import time
from urllib import quote_plus, urlencode
from hmac import HMAC
import random
import string

def generate_sas_token(uri, key, policy_name, expiry=3600):
    ttl = time() + expiry
    sign_key = "%s\n%d" % ((quote_plus(uri)), int(ttl))
    print(" - Sign Key:")
    print (sign_key)
    signature = b64encode(HMAC(b64decode(key), sign_key, sha256).digest())

    rawtoken = {
        'sr' :  uri,
        'sig': signature,
        'se' : str(int(ttl)),
        'skn' : policy_name
    }

    return 'SharedAccessSignature ' + urlencode(rawtoken)

key = "HzbOQK2O7ugc01deqBq+ak+e8QmmHKwHevqhxnrcA8LFXXXXXXXXXXXXXXXXXXXXXXXXXXXX" # This is the DPS Device Primary Key
uri = "0ne009XXXXXXX/registrations/dps-test-device-1" # Create this uri with format: <dps_scope_id>/registrations/<device_id>
policy_name = "registration" # Leave this value as is

newsastoken = generate_sas_token(uri, key, policy_name)
print(" - URI:")
print(uri)
print(" - The following output will be used in the Authorization Header:")
print(newsastoken)
