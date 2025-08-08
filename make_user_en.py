import requests
import random
import csv
import json
import logging
import secrets
import os
from pathlib import Path
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
from bech32 import bech32_encode, convertbits
from datetime import datetime, timedelta
from dotenv import load_dotenv

# -----------------------------------------------------------------------------
# CONFIG (strict: all values must be in .env)
# -----------------------------------------------------------------------------
load_dotenv()

def require_env(key: str) -> str:
    v = os.getenv(key)
    if not v or not v.strip():
        raise SystemExit(f"ENV error: '{key}' is required in .env")
    return v.strip()

# Base + endpoints
LNBits_API_BASE        = require_env("LNBITS_API_BASE")
LNBits_LOGIN_URL       = f"{LNBits_API_BASE}/api/v1/auth"
LNBits_CREATE_URL      = f"{LNBits_API_BASE}/api/v1/account"
LNBits_USER_UPDATE_URL = f"{LNBits_API_BASE}/users/api/v1/user"
LNBits_NIP5_PUBLIC_URL = f"{LNBits_API_BASE}/nostrnip5/api/v1/public/domain"
LNBits_NWC_PAIRING_URL = f"{LNBits_API_BASE}/nwcprovider/api/v1/pairing"

# Credentials & domain
ADMIN_USERNAME = require_env("LNBITS_ADMIN_USERNAME")
ADMIN_PASSWORD = require_env("LNBITS_ADMIN_PASSWORD")
DOMAIN         = require_env("DOMAIN")
DOMAIN_ID      = require_env("DOMAIN_ID")

# Relays (strict)
NWC_RELAY_URL = require_env("NWC_RELAY_URL")  # must start with wss://
NIP5_RELAYS   = [r.strip() for r in require_env("NIP5_RELAYS").split(",") if r.strip()]
if not NWC_RELAY_URL.startswith("wss://"):
    raise SystemExit("ENV error: NWC_RELAY_URL must start with wss://")

# File paths (strict; from .env only)
CSV_ACCOUNTS  = Path(require_env("CSV_ACCOUNTS"))
CSV_WALLETS   = Path(require_env("CSV_WALLETS"))
CSV_SECRETS   = Path(require_env("CSV_SECRETS"))
CSV_KEYSOURCE = Path(require_env("CSV_KEYSOURCE"))
LOG_FILE      = Path(require_env("LOG_FILE"))

# -----------------------------------------------------------------------------
# LOGGING
# -----------------------------------------------------------------------------
if LOG_FILE.exists():
    LOG_FILE.unlink()

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

LOGGER = logging.getLogger(__name__)

LINE = "=" * 80
SUB  = "-" * 80
GAP  = "\n"

def section(title: str):
    LOGGER.debug(GAP + LINE)
    LOGGER.debug(title)
    LOGGER.debug(LINE + GAP)

def subsection(title: str):
    LOGGER.debug(SUB)
    LOGGER.debug(title)
    LOGGER.debug(SUB)

# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------
session = requests.Session()

def admin_login():
    section("[FUNCTION] admin_login")
    try:
        resp = session.post(LNBits_LOGIN_URL, json={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        })
        resp.raise_for_status()
        LOGGER.debug("✅ Admin login successful, session cookie acquired.")
        return True
    except Exception as e:
        LOGGER.critical(f"❌ Admin login failed: {e}")
        LOGGER.debug(f"Status: {getattr(resp, 'status_code', 'unknown')}")
        LOGGER.debug(f"Response: {getattr(resp, 'text', '')}")
        return False

def random_string(length=8):
    return ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=length))

def to_bech32(prefix, hexkey):
    data = bytes.fromhex(hexkey)
    five_bit = convertbits(data, 8, 5, True)
    return bech32_encode(prefix, five_bit)

def generate_nostr_keys(mnemonic_words=None):
    section("[FUNCTION] generate_nostr_keys")
    mnemo = Mnemonic("english")
    if not mnemonic_words:
        mnemonic_words = mnemo.generate(strength=128)
        LOGGER.debug("Generated new 12-word mnemonic.")
    else:
        LOGGER.debug("Using provided mnemonic.")

    seed_bytes = Bip39SeedGenerator(mnemonic_words).Generate()
    bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
    derived = bip32_ctx.DerivePath("m/44'/1237'/0'/0/0")

    privkey_hex = derived.PrivateKey().Raw().ToBytes().hex()
    # Nostr x-only pubkey = 32-byte X coordinate (drop 0x02/0x03 prefix from compressed key)
    pubkey_hex = derived.PublicKey().RawCompressed().ToBytes()[1:].hex()

    keys = {
        "privkey_hex": privkey_hex,
        "pubkey_hex": pubkey_hex,
        "nsec": to_bech32("nsec", privkey_hex),
        "npub": to_bech32("npub", pubkey_hex),
        "mnemonic": mnemonic_words
    }
    LOGGER.debug("Derived Nostr keys:")
    LOGGER.debug(json.dumps({k: (v if k not in ("privkey_hex", "mnemonic") else "***") for k, v in keys.items()}, indent=2))
    return keys

def encode_lnurl(url):
    url_bytes = url.encode("utf-8")
    data = convertbits(url_bytes, 8, 5)
    return bech32_encode("lnurl", data)

def update_user(user_id, username, pubkey):
    section("[FUNCTION] update_user")
    url = f"{LNBits_USER_UPDATE_URL}/{user_id}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "id": user_id,
        "email": f"{username}@{DOMAIN}",
        "username": username,
        "pubkey": pubkey,
        "external_id": "",
        "extensions": ["lnurlp", "lndhub", "nwcprovider"],
        "extra": {
            "email_verified": False,
            "provider": "lnbits",
            "visible_wallet_count": 10
        }
    }
    subsection("PUT /users/api/v1/user/{id}")
    LOGGER.debug(f"URL: {url}")
    LOGGER.debug(f"Payload:\n{json.dumps(payload, indent=2)}")
    try:
        resp = session.put(url, headers=headers, json=payload)
        ok = resp.status_code == 200
        LOGGER.debug(f"Result: {'✅ OK' if ok else '❌ FAILED'} (status={resp.status_code})")
        if not ok:
            LOGGER.debug(f"Response: {resp.text}")
        return ok
    except Exception as e:
        LOGGER.error(f"❌ Error updating user '{username}': {e}")
        return False

def activate_extensions(user_id):
    section("[FUNCTION] activate_extensions")
    for ext in ["lnurlp", "lndhub", "nwcprovider"]:
        url = f"{LNBits_API_BASE}/api/v1/extension/{ext}/activate"
        subsection(f"Activate extension: {ext}")
        LOGGER.debug(f"PUT {url}?usr={user_id}")
        try:
            resp = session.put(url, params={"usr": user_id})
            LOGGER.debug(f"Result: {'✅ OK' if resp.ok else '❌ FAILED'} (status={resp.status_code})")
            if not resp.ok:
                LOGGER.debug(f"Response: {resp.text}")
        except Exception as e:
            LOGGER.error(f"❌ Error activating '{ext}': {e}")

def configure_lnaddress_public(username, pubkey):
    section("[FUNCTION] configure_lnaddress_public")
    url = f"{LNBits_NIP5_PUBLIC_URL}/{DOMAIN_ID}/address"
    payload = {
        "domain_id": DOMAIN_ID,
        "local_part": username,
        "pubkey": pubkey,
        "years": 1,
        "relays": NIP5_RELAYS,
        "create_invoice": True,
        "active": True,
        "is_locked": False
    }
    subsection("POST /nostrnip5/api/v1/public/domain/{id}/address")
    LOGGER.debug(f"URL: {url}")
    LOGGER.debug(f"Payload:\n{json.dumps(payload, indent=2)}")
    try:
        resp = session.post(url, json=payload)
        LOGGER.debug(f"Result: {'✅ OK' if resp.ok else '❌ FAILED'} (status={resp.status_code})")
        if not resp.ok:
            LOGGER.debug(f"Response: {resp.text}")
    except Exception as e:
        LOGGER.error(f"❌ Error configuring NIP-05 LN address for '{username}': {e}")

# -----------------------------------------------------------------------------
# NWC CREATION (UI-COMPATIBLE): x-only pubkey, SHA256(secret_raw) as hex
# -----------------------------------------------------------------------------
from datetime import datetime, UTC
from hashlib import sha256
from coincurve import PrivateKey
import re

def build_nwc_link(pubkey, secret):
    return f"nostr+walletconnect://{pubkey}?relay={NWC_RELAY_URL}&secret={secret}"

def verify_nwc_pairing(secret, expected_pubkey=None):
    section("[FUNCTION] verify_nwc_pairing")
    url = f"{LNBits_NWC_PAIRING_URL}/{secret}"
    subsection("GET /nwcprovider/api/v1/pairing/{secret}")
    LOGGER.debug(f"URL: {url}")
    try:
        resp = session.get(url)
        resp.raise_for_status()
        pairing_link = resp.text.strip()
        LOGGER.debug(f"✅ Pairing link received: {pairing_link}")

        # Extract pubkey from returned link
        actual_pubkey = pairing_link.split("://")[1].split("?")[0]
        LOGGER.debug(f"Extracted pubkey from link: {actual_pubkey}")

        if expected_pubkey:
            match = (actual_pubkey == expected_pubkey)
            LOGGER.debug(f"Pubkey match: {'✅ YES' if match else '❌ NO'}")
            if not match:
                LOGGER.warning("⚠️ Pairing pubkey differs from requested pubkey!")
                LOGGER.warning(f"Expected: {expected_pubkey}")
                LOGGER.warning(f"Actual:   {actual_pubkey}")

        return actual_pubkey
    except Exception as e:
        LOGGER.error(f"❌ Error retrieving /pairing/{secret}: {e}")
        LOGGER.debug(f"Status: {getattr(resp, 'status_code', 'unknown')}")
        LOGGER.debug(f"Response: {getattr(resp, 'text', '')}")
        return None

def create_nwc_key(username, wallet_id, created_at, lnbits_url, session, user_api_key):
    section("[FUNCTION] create_nwc_key")
    LOGGER.debug(f"User:          {username}")
    LOGGER.debug(f"Wallet ID:     {wallet_id}")
    LOGGER.debug(f"User AdminKey: {user_api_key}")
    LOGGER.debug(f"Created at:    {created_at}")

    # 1) Generate secret (32B random -> sha256 hex)
    subsection("Generate secret and keys")
    secret_raw = secrets.token_bytes(32)
    secret_hex = sha256(secret_raw).hexdigest().lower()

    # 2) Derive Nostr x-only pubkey (32B hex)
    privkey = PrivateKey(bytes.fromhex(secret_hex))
    pubkey_hex = privkey.public_key.format(compressed=True)[1:].hex()  # drop prefix -> 32B

    # 3) Sanity checks in logs
    LOGGER.debug(f"Secret (hex, 64 chars): {secret_hex}  [len={len(secret_hex)}]")
    LOGGER.debug(f"Pubkey (x-only, 64):    {pubkey_hex}  [len={len(pubkey_hex)}]")
    assert re.fullmatch(r"[0-9a-f]{64}", secret_hex), "Secret must be 64 hex chars"
    assert re.fullmatch(r"[0-9a-f]{64}", pubkey_hex), "Pubkey must be 64 hex chars"

    # 4) PUT request to create NWC key
    subsection("PUT NWC key to LNbits")
    put_url = f"{lnbits_url}/nwcprovider/api/v1/nwc/{pubkey_hex}"
    headers = {"Content-Type": "application/json", "X-Api-Key": user_api_key}
    payload = {
        "description": username,
        "expires_at": 0,
        "permissions": ["pay", "invoice", "lookup", "history", "balance", "info"],
        "budgets": [{
            "pubkey": pubkey_hex,
            "budget_msats": 0,
            "refresh_window": 86400,
            "created_at": created_at
        }],
        "secret": secret_hex  # 32B hex string (64 chars)
    }
    LOGGER.debug(f"PUT {put_url}")
    LOGGER.debug(f"Payload:\n{json.dumps(payload, indent=2)}")

    try:
        resp = session.put(put_url, headers=headers, json=payload)
        resp.raise_for_status()
        LOGGER.debug("✅ NWC key successfully created.")
    except Exception as e:
        LOGGER.error(f"❌ NWC key creation failed: {e}")
        LOGGER.debug(f"Status: {getattr(resp, 'status_code', 'unknown')}")
        LOGGER.debug(f"Response: {getattr(resp, 'text', '')}")
        return None, None, None

    # 5) Build link and verify
    subsection("Build NWC link and verify pairing")
    nwc_url = build_nwc_link(pubkey_hex, secret_hex)
    LOGGER.debug(f"Final NWC link: {nwc_url}")

    actual_pubkey = verify_nwc_pairing(secret_hex, expected_pubkey=pubkey_hex)
    if actual_pubkey and actual_pubkey != pubkey_hex:
        LOGGER.warning("⚠️ Pairing pubkey differs from requested pubkey!")
        LOGGER.warning(f"Expected: {pubkey_hex}")
        LOGGER.warning(f"Actual:   {actual_pubkey}")

    return nwc_url, pubkey_hex, secret_hex

# -----------------------------------------------------------------------------
# LNURLp + LNDHub helpers
# -----------------------------------------------------------------------------
def create_lnurlp_link(username, wallet_id, adminkey):
    section("[FUNCTION] create_lnurlp_link")
    url = f"{LNBits_API_BASE}/lnurlp/api/v1/links"
    headers = {"Content-Type": "application/json", "X-Api-Key": adminkey}
    payload = {
        "description": f"{username} LNURLp",
        "min": 1,
        "max": 1000000,
        "username": username,
        "nostr": True,
        "wallet": wallet_id,
        "comment_chars": 120,
        "currency": None,
        "amount": 0,
        "success_text": "Zap! ⚡"
    }
    subsection("POST /lnurlp/api/v1/links")
    LOGGER.debug(f"URL: {url}")
    LOGGER.debug(f"Payload:\n{json.dumps(payload, indent=2)}")

    try:
        resp = session.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        link_id = resp.json()["id"]
        raw_url = f"{LNBits_API_BASE}/lnurlp/{link_id}"
        lnurl = encode_lnurl(raw_url)
        LOGGER.debug(f"✅ LNURLp created: {lnurl}")
        return lnurl
    except Exception as e:
        LOGGER.error(f"❌ Failed to create LNURLp link for '{username}': {e}")
        LOGGER.debug(f"Status: {getattr(resp, 'status_code', 'unknown')}")
        LOGGER.debug(f"Response: {getattr(resp, 'text', '')}")
        return ""

def get_lndhub_admin_url(adminkey):
    # Note: uses full API base; if you need just the host, parse accordingly.
    return f"lndhub://admin:{adminkey}@{LNBits_API_BASE}/lndhub/ext/"

# -----------------------------------------------------------------------------
# USER CREATION
# -----------------------------------------------------------------------------
def create_user(username, mnemonic_words=None, nostr_pubkey_hex=None):
    section("[FUNCTION] create_user")
    LOGGER.debug(f"Starting user creation for: {username}")

    # 1) Keys: use external pubkey or generate keys
    subsection("Prepare Nostr keys")
    if nostr_pubkey_hex:
        keys = {
            "privkey_hex": "",
            "pubkey_hex": nostr_pubkey_hex,
            "nsec": "",
            "npub": "",
            "mnemonic": ""
        }
        LOGGER.debug(f"Using external Nostr public key for '{username}': {nostr_pubkey_hex}")
    else:
        keys = generate_nostr_keys(mnemonic_words)
        LOGGER.debug(f"Generated Nostr keys for '{username}' (private values masked).")

    password = random_string()
    email = f"{username}@{DOMAIN}"

    try:
        # 2) Create account
        subsection("Create LNbits account")
        LOGGER.debug(f"POST {LNBits_CREATE_URL}")
        resp = session.post(LNBits_CREATE_URL, json={"name": username, "password": password})
        resp.raise_for_status()
        data = resp.json()

        user_id = data["user"]
        adminkey = data["adminkey"]
        LOGGER.debug(f"User ID: {user_id}")
        LOGGER.debug(f"AdminKey: {adminkey}")

        # 3) Fetch auto-created wallet
        subsection("Fetch auto-created wallet")
        wallet_list_url = f"{LNBits_API_BASE}/users/api/v1/user/{user_id}/wallet"
        LOGGER.debug(f"GET {wallet_list_url}")
        wallet_resp = session.get(wallet_list_url)
        wallet_resp.raise_for_status()
        wallet_list = wallet_resp.json()
        if not isinstance(wallet_list, list) or not wallet_list:
            raise Exception(f"No wallet automatically created for '{username}'")

        wallet_obj = wallet_list[0]
        wallet_id = wallet_obj["id"]
        inkey = wallet_obj.get("inkey", "")

        LOGGER.debug(f"Wallet ID: {wallet_id}")
        LOGGER.debug(f"Wallet inkey: {inkey}")

        # 4) Update user and activate extensions
        subsection("Update user + activate extensions + configure NIP-05")
        update_user(user_id, username, keys["pubkey_hex"])
        activate_extensions(user_id)
        configure_lnaddress_public(username, keys["pubkey_hex"])

        # 5) Create NWC key (UI-like flow)
        created_at = int(datetime.utcnow().timestamp())
        subsection("Create NWC key (UI-compatible)")
        LOGGER.debug(f"Expected user pubkey_hex: {keys['pubkey_hex']}")
        LOGGER.debug(f"created_at: {created_at}")

        nwc_url, actual_nwc_pubkey, nwc_secret = create_nwc_key(
            username=username,
            wallet_id=wallet_id,
            created_at=created_at,
            lnbits_url=LNBits_API_BASE,
            session=session,
            user_api_key=adminkey
        )

        if actual_nwc_pubkey and keys["pubkey_hex"] and actual_nwc_pubkey != keys["pubkey_hex"]:
            LOGGER.warning("⚠️ NWC pubkey differs from user pubkey!")
            LOGGER.warning(f"Expected: {keys['pubkey_hex']}")
            LOGGER.warning(f"Actual:   {actual_nwc_pubkey}")

        # 6) LNURLp + LNDHub URLs
        subsection("Create LNURLp + LNDHub URLs")
        lnurlp_link = create_lnurlp_link(username, wallet_id, adminkey)
        lndhub_url = get_lndhub_admin_url(adminkey)

        return {
            "account": {
                "id": user_id,
                "email": email,
                "password_hash": "****",
                "username": username,
                "extra": "{}",
                "created_at": data.get("created_at", ""),
                "updated_at": data.get("updated_at", ""),
                "pubkey": keys["pubkey_hex"],
                "access_control_list": "[]",
                "npub": keys["npub"],
                "external_id": ""
            },
            "wallet": {
                "id": wallet_id,
                "name": username,
                "user": user_id,
                "adminkey": adminkey,
                "inkey": inkey,
                "currency": wallet_obj.get("currency", "USD"),
                "deleted": wallet_obj.get("deleted", False),
                "created_at": wallet_obj.get("created_at", ""),
                "updated_at": wallet_obj.get("updated_at", ""),
                "extra": json.dumps(wallet_obj.get("extra", {}))
            },
            "secret": {
                "user_id": user_id,
                "username": username,
                "email": email,
                "npub": keys["npub"],
                "nsec": keys["nsec"],
                "mnemonic": keys["mnemonic"],
                "privkey_hex": keys["privkey_hex"],
                "pubkey_hex": keys["pubkey_hex"],
                "wallet_inkey": inkey,
                "wallet_adminkey": adminkey,
                "nwc_secret": nwc_secret,
                "nwc_link": nwc_url,
                "nwc_pubkey_actual": actual_nwc_pubkey or "",
                "lnurlp_link": lnurlp_link,
                "lndhub_admin_url": lndhub_url
            }
        }

    except Exception as e:
        LOGGER.exception(f"❌ Exception while creating user '{username}':")
        return None

# -----------------------------------------------------------------------------
# CSV + MAIN
# -----------------------------------------------------------------------------
def load_existing_usernames():
    section("[FUNCTION] load_existing_usernames")
    if not CSV_ACCOUNTS.exists():
        LOGGER.debug("Accounts CSV does not exist yet.")
        return set()
    with open(CSV_ACCOUNTS, "r", newline="") as f:
        names = {row["username"] for row in csv.DictReader(f)}
    LOGGER.debug(f"Loaded {len(names)} existing usernames.")
    return names

def load_mnemonic_map():
    section("[FUNCTION] load_mnemonic_map")
    if not CSV_KEYSOURCE.exists():
        LOGGER.debug("Mnemonic CSV does not exist; skipping.")
        return {}
    with open(CSV_KEYSOURCE, "r", newline="") as f:
        reader = csv.DictReader(f, delimiter=';')  # keep ';' if your file uses semicolons
        m = {row["username"]: row["mnemonic"] for row in reader if row.get("mnemonic")}
    LOGGER.debug(f"Loaded {len(m)} mnemonic entries.")
    return m

def is_empty(fp): 
    return (not fp.exists()) or (fp.stat().st_size == 0)

if __name__ == "__main__":
    section("[MAIN] Startup")

    print("Select mode:")
    print("  1 = Enter users manually")
    print("  2 = Generate 3 random usernames")
    print("  3 = Load users + mnemonics from CSV file")
    mode = input("Selection [1/2/3]: ").strip()

    usernames = []
    mnemonic_map = {}

    if mode == "2":
        usernames = [random_string(8) for _ in range(3)]

    elif mode == "3":
        csv_file = input("📂 Enter CSV filename (e.g.: mnemonic.csv): ").strip()
        csv_path = Path(csv_file)
        if not csv_path.exists():
            LOGGER.critical(f"❌ CSV file not found: {csv_file}")
            exit(1)
        with open(csv_path, "r", newline="") as f:
            reader = csv.DictReader(f, delimiter=';')  # adjust if your CSV uses commas
            for row in reader:
                if row.get("username"):
                    usernames.append(row["username"])
                    if row.get("mnemonic"):
                        mnemonic_map[row["username"]] = row["mnemonic"]
        LOGGER.info("📄 Users loaded from CSV.")

    else:
        usernames = input("📝 Enter usernames separated by spaces: ").split()

    if not usernames:
        LOGGER.error("❌ No usernames provided.")
        exit(1)

    nostr_pubkey_hex = input("🔑 Optional: Nostr Public Key (hex, leave empty to auto-generate): ").strip() or None

    if not admin_login():
        exit(1)

    existing = load_existing_usernames()

    with open(CSV_ACCOUNTS, "a", newline="") as fa, \
         open(CSV_WALLETS, "a", newline="") as fw, \
         open(CSV_SECRETS, "a", newline="") as fs:

        acc = csv.DictWriter(fa, fieldnames=[
            "id", "email", "password_hash", "username", "extra",
            "created_at", "updated_at", "pubkey", "access_control_list", "npub", "external_id"
        ])
        wal = csv.DictWriter(fw, fieldnames=[
            "id", "name", "user", "adminkey", "inkey",
            "currency", "deleted", "created_at", "updated_at", "extra"
        ])
        sec = csv.DictWriter(fs, fieldnames=[
            "user_id", "username", "email", "npub", "nsec", "mnemonic",
            "privkey_hex", "pubkey_hex", "wallet_inkey", "wallet_adminkey",
            "nwc_secret", "nwc_link", "nwc_pubkey_actual",
            "lnurlp_link", "lndhub_admin_url"
        ])

        if is_empty(CSV_ACCOUNTS): acc.writeheader()
        if is_empty(CSV_WALLETS): wal.writeheader()
        if is_empty(CSV_SECRETS): sec.writeheader()

        section("[MAIN] Creating users")
        for name in usernames:
            if name in existing:
                LOGGER.info(f"⏩ User skipped (already exists): {name}")
                continue

            mnemonic = mnemonic_map.get(name)
            result = create_user(name, mnemonic, nostr_pubkey_hex)

            if result:
                acc.writerow(result["account"])
                wal.writerow(result["wallet"])
                sec.writerow(result["secret"])
                LOGGER.info("✅ User successfully created.")
            else:
                LOGGER.error(f"❌ Failed to create user: {name}")