"""Constants for Kasa KLAP v2."""

DOMAIN = "kasa_klap_v2"

ISSUE_INCOMPATIBLE = "incompatible"
ISSUE_NOT_NEEDED = "not_needed"

# TP-Link keeps each device's credential hash under this key in its entry data.
TPLINK_DOMAIN = "tplink"
CONF_CREDENTIALS_HASH = "credentials_hash"

STORAGE_KEY = f"{DOMAIN}.credentials_hashes"
STORAGE_VERSION = 1
