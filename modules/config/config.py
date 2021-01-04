SECURE = False
API = "https://127.0.0.1:443/api/v1"

SERVER_URL = "https://127.0.0.1:443"  # Main Server URL
EXP_RATE = 11  # This is the rate at which users will get exp per concept
CSRF_SECRET_1 = "1f03eea1ffb7446294f71342bf110f21b91a849377"
CSRF_SECRET_2 = "144b789219a6a314ffb7815a0b69b2d6274bae84dd66b734393241"
SESSION_SECRET_1 = "iiqEEZ0z1wXWeJ3lRJnPsamlvbmEq4tesBDJ38HD3dj329Ddrejrj34jf"
SESSION_SECRET_2 = "jrc4j3fwkjVrT34jkFj34jkgce3jfqkeieiei3jd44584830290riuejn"
SESSION_SECRET_3 = "fdiuwrjncjnwe8uefhnewfu553kf84EyfFH48SHSWk"
AUTH_LIMIT = 7 # Auth Rate Limit

# Important Stuff
CSRF_SECRET = CSRF_SECRET_1 + CSRF_SECRET_2
SESSION_SECRET = SESSION_SECRET_1 + SESSION_SECRET_2 + SESSION_SECRET_3
