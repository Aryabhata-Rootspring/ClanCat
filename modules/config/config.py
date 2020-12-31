SECURE = False
API = "https://127.0.0.1:443/api/v1"

SERVER_URL = "https://127.0.0.1:443"  # Main Server URL
HASH_SALT_1 = "66801b86-06ff-49c7-a163-eeda39b8cba9"
HASH_SALT_2 = "_66bc6c6c-24e3-11eb-adc1-0242a"
HASH_SALT_3 = "c120002_66bc6c6c-24e3-11eb-adc1-0242ac120002"
EXP_RATE = 11  # This is the rate at which users will get exp per concept
CSRF_SECRET_1 = "1f03eea1ffb7446294f71342bf110f21b91a849377"
CSRF_SECRET_2 = "144b789219a6a314ffb7815a0b69b2d6274bae84dd66b734393241"


# Important Stuff
HASH_SALT = HASH_SALT_1 + HASH_SALT_2 + HASH_SALT_3
CSRF_SECRET = CSRF_SECRET_1 + CSRF_SECRET_2
