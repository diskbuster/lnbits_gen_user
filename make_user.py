import requests
import random
import csv
import json
import logging
import secrets
from pathlib import Path
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
from bech32 import bech32_encode, convertbits
from datetime import datetime, timedelta

# === KONFIGURATION ===
LNBits_API_BASE = "https://lnbits.nsnip.io"
LNBits_LOGIN_URL = f"{LNBits_API_BASE}/api/v1/auth"
LNBits_CREATE_URL = f"{LNBits_API_BASE}/api/v1/account"
LNBits_USER_UPDATE_URL = f"{LNBits_API_BASE}/users/api/v1/user"
LNBits_NIP5_PUBLIC_URL = f"{LNBits_API_BASE}/nostrnip5/api/v1/public/domain"
LNBits_NWC_PAIRING_URL = f"{LNBits_API_BASE}/nwcprovider/api/v1/pairing"
NWC_PROVIDER_PUBKEY = "7bea3415250cd3c37d6094d226bd236713939c9b82b3897579f5baa52d517d6b"
DOMAIN = "nsnip.io"
DOMAIN_ID = "jUGMtFMYzA2e4w7wmnfaWj"
ADMIN_USERNAME = "superadmin"
ADMIN_PASSWORD = "M0insen!23"

CSV_ACCOUNTS = Path("lnbits_accounts.csv")
CSV_WALLETS = Path("lnbits_wallets.csv")
CSV_SECRETS = Path("lnbits_secrets.csv")
CSV_KEYSOURCE = Path("mnemonic.csv")
LOG_FILE = Path("lnbits_user_creation.log")

# Logging
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

session = requests.Session()

def admin_login():
    try:
        resp = session.post(LNBits_LOGIN_URL, json={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        })
        resp.raise_for_status()
        logging.debug("✅ Admin-Cookie erhalten.")
        return True
    except Exception as e:
        logging.critical(f"❌ Fehler beim Admin-Login: {e}")
        return False

def random_string(length=8):
    return ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=length))

def to_bech32(prefix, hexkey):
    data = bytes.fromhex(hexkey)
    five_bit = convertbits(data, 8, 5, True)
    return bech32_encode(prefix, five_bit)

def generate_nostr_keys(mnemonic_words=None):
    mnemo = Mnemonic("english")
    if not mnemonic_words:
        mnemonic_words = mnemo.generate(strength=128)
    seed_bytes = Bip39SeedGenerator(mnemonic_words).Generate()
    bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
    derived = bip32_ctx.DerivePath("m/44'/1237'/0'/0/0")
    privkey_hex = derived.PrivateKey().Raw().ToBytes().hex()
    pubkey_hex = derived.PublicKey().RawCompressed().ToBytes()[1:].hex()
    return {
        "privkey_hex": privkey_hex,
        "pubkey_hex": pubkey_hex,
        "nsec": to_bech32("nsec", privkey_hex),
        "npub": to_bech32("npub", pubkey_hex),
        "mnemonic": mnemonic_words
    }

def encode_lnurl(url):
    url_bytes = url.encode("utf-8")
    data = convertbits(url_bytes, 8, 5)
    return bech32_encode("lnurl", data)
    


def update_user(user_id, username, pubkey):
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
    try:
        resp = session.put(url, headers=headers, json=payload)
        return resp.status_code == 200
    except Exception as e:
        logging.error(f"❌ Fehler beim Update von {username}: {e}")
        return False

def activate_extensions(user_id):
    for ext in ["lnurlp", "lndhub", "nwcprovider"]:
        url = f"{LNBits_API_BASE}/api/v1/extension/{ext}/activate"
        try:
            session.put(url, params={"usr": user_id})
        except Exception as e:
            logging.error(f"❌ Fehler beim Aktivieren von {ext}: {e}")

def configure_lnaddress_public(username, pubkey):
    url = f"{LNBits_NIP5_PUBLIC_URL}/{DOMAIN_ID}/address"
    payload = {
        "domain_id": DOMAIN_ID,
        "local_part": username,
        "pubkey": pubkey,
        "years": 1,
        "relays": ["wss://relay.nsnip.io"],
        "create_invoice": True,
        "active": True,
        "is_locked": False
    }
    try:
        session.post(url, json=payload)
    except Exception as e:
        logging.error(f"❌ Fehler bei LNURL für {username}: {e}")


import re  # Wichtig für Pubkey-Extraktion aus der URL

def create_nwc_key(
	username,
	wallet_id,
	created_at,
	lnbits_url,
	session,
	user_api_key
):
	import hashlib
	import hmac

	logger = logging.getLogger(__name__)
	logger.debug("\n" + "=" * 80)
	logger.debug(f"🔑 [NWC] Starte NWC-Schlüssel-Erstellung für Benutzer: {username}")
	logger.debug(f"🔧 Wallet-ID: {wallet_id}")
	logger.debug(f"🔐 Benutzer-AdminKey: {user_api_key}")
	logger.debug(f"📅 Timestamp (created_at): {created_at}")
	logger.debug("=" * 80 + "\n")

	# Schritt 1: Secret erzeugen (32 Byte hex)
	secret = secrets.token_hex(32)
	logger.debug(f"📡 Schritt 1: Secret erzeugt: {secret}")

	# Schritt 2: Nostr Pubkey aus Secret erzeugen (wie in nwcprovider)
	try:
		seed_bytes = bytes.fromhex(secret)
		master_key = hmac.new(b"ed25519 seed", seed_bytes, hashlib.sha512).digest()
		master_secret = master_key[:32]
		from nacl.signing import SigningKey
		signing_key = SigningKey(master_secret)
		verify_key = signing_key.verify_key
		actual_pubkey = verify_key.encode().hex()
		logger.debug(f"✅ Schritt 2: Pubkey aus Secret generiert (nwcprovider-style): {actual_pubkey}")
	except Exception as e:
		logger.error(f"❌ Fehler bei der Pubkey-Berechnung aus Secret: {e}")
		return None, None

	# Schritt 3: PUT-Request zum Erstellen des NWC-Schlüssels
	put_url = f"{lnbits_url}/nwcprovider/api/v1/nwc/{actual_pubkey}"
	headers = {
		"Content-Type": "application/json",
		"X-Api-Key": user_api_key
	}
	payload = {
		"description": username,
		"expires_at": 0,
		"permissions": [
			"pay", "invoice", "lookup", "history", "balance", "info"
		],
		"budgets": [
			{
				"pubkey": actual_pubkey,
				"budget_msats": 0,
				"refresh_window": 86400,
				"created_at": created_at
			}
		]
	}

	logger.debug(f"\n🛠 Schritt 3: Senden des PUT-Requests zur Erstellung des NWC-Schlüssels")
	logger.debug(f"➡️  PUT {put_url}")
	logger.debug(f"📤 Payload:\n{json.dumps(payload, indent=2)}")

	try:
		resp = session.put(put_url, headers=headers, json=payload)
		resp.raise_for_status()
		logger.debug("✅ NWC-Schlüssel erfolgreich erstellt.")
	except Exception as e:
		logger.error(f"❌ Fehler beim Erstellen des NWC-Schlüssels: {e}")
		logger.error(f"📄 Antwortstatus: {getattr(resp, 'status_code', 'unbekannt')}")
		logger.error(f"📄 Antwortinhalt: {getattr(resp, 'text', '')}")
		return None, None

	# Schritt 4: NWC-Link zusammenbauen
	relay = "wss://lnbits.nsnip.io/nostrclient/api/v1/relay"
	nwc_link = f"nostr+walletconnect://{actual_pubkey}?relay={relay}&secret={secret}"
	logger.debug(f"\n🔗 Schritt 4: Fertiger NWC-Link: {nwc_link}")

	return nwc_link, actual_pubkey

def create_lnurlp_link(username, wallet_id, adminkey):
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
    try:
        resp = session.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        link_id = resp.json()["id"]
        raw_url = f"{LNBits_API_BASE}/lnurlp/{link_id}"
        return encode_lnurl(raw_url)
    except Exception as e:
        logging.error(f"❌ Fehler beim Erstellen des LNURLp-Links für {username}: {e}")
        return ""

def get_lndhub_admin_url(adminkey):
    return f"lndhub://admin:{adminkey}@{LNBits_API_BASE}/lndhub/ext/"
	
def build_nwc_link(pubkey, secret):
	relay = "wss://lnbits.nsnip.io/nostrclient/api/v1/relay"
	return f"nostr+walletconnect://{pubkey}?relay={relay}&secret={secret}"
	
def verify_nwc_pairing(secret, expected_pubkey=None):
    url = f"{LNBits_NWC_PAIRING_URL}/{secret}"
    try:
        resp = session.get(url)
        resp.raise_for_status()
        pairing_link = resp.text.strip()
        logging.debug(f"✅ NWC-Pairing-Link erhalten: {pairing_link}")
    
        # Pubkey extrahieren
        actual_pubkey = pairing_link.split("://")[1].split("?")[0]
        logging.debug(f"🔍 Tatsächlicher Pubkey im Link: {actual_pubkey}")
    
        if expected_pubkey:
            match = "✅" if actual_pubkey == expected_pubkey else "❌"
            logging.debug(f"{match} Erwarteter Pubkey: {expected_pubkey}")
            if match == "❌":
                logging.warning(f"❌ Pubkey stimmt nicht überein! Erwartet: {expected_pubkey}, Erhalten: {actual_pubkey}")
    
        return actual_pubkey
    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen von /pairing/{secret}: {e}")
        return None

def create_user(username, mnemonic_words=None, nostr_pubkey_hex=None):
        logging.debug("\n" + "=" * 80)
        logging.debug(f"🚀 [USER] Starte Erstellung für Benutzer: {username}")
        logging.debug("=" * 80)
        
        # 1. Schlüsselerzeugung oder Verwendung
        if nostr_pubkey_hex:
            keys = {
                "privkey_hex": "",
                "pubkey_hex": nostr_pubkey_hex,
                "nsec": "",
                "npub": "",
                "mnemonic": ""
            }
            logging.debug(f"🔐 Verwende externen Nostr Public Key für {username}: {nostr_pubkey_hex}")
        else:
            keys = generate_nostr_keys(mnemonic_words)
            logging.debug(f"🔐 Generierte Nostr-Keys für {username}:\n{json.dumps(keys, indent=2)}")
        
        password = random_string()
        email = f"{username}@{DOMAIN}"
        
        # 🧠 Neuer NWC-Key wird separat erzeugt (wie im UI)
        nwc_keys = generate_nostr_keys()
        secret = nwc_keys["privkey_hex"]
        nwc_pubkey = nwc_keys["pubkey_hex"]
        
        try:
            # 2. Benutzer-Account erstellen
            resp = session.post(LNBits_CREATE_URL, json={"name": username, "password": password})
            resp.raise_for_status()
            data = resp.json()
        
            user_id = data["user"]
            adminkey = data["adminkey"]
            logging.debug(f"\n🆔 Benutzer-ID: {user_id}, AdminKey: {adminkey}")
        
            # 3. Wallet holen
            wallet_list_url = f"{LNBits_API_BASE}/users/api/v1/user/{user_id}/wallet"
            wallet_resp = session.get(wallet_list_url)
            wallet_list = wallet_resp.json()
            if not isinstance(wallet_list, list) or not wallet_list:
                raise Exception(f"❌ Keine Wallet automatisch erstellt für {username}")
        
            wallet_obj = wallet_list[0]
            wallet_id = wallet_obj["id"]
            inkey = wallet_obj.get("inkey", "")
        
            logging.debug(f"💼 Wallet-ID: {wallet_id}")
            logging.debug(f"🔑 Wallet-Inkey: {inkey}")
        
            # 4. Userdaten aktualisieren und Extensions aktivieren
            update_user(user_id, username, keys["pubkey_hex"])
            activate_extensions(user_id)
            configure_lnaddress_public(username, keys["pubkey_hex"])
        
            # 5. NWC-Key wie im UI erzeugen
            created_at = int(datetime.utcnow().timestamp())
            logging.debug("\n" + "=" * 80)
            logging.debug(f"🔑 [NWC] Starte NWC-Schlüssel-Erstellung für Benutzer: {username}")
            logging.debug(f"🔧 Wallet-ID: {wallet_id}")
            logging.debug(f"🔐 Benutzer-AdminKey: {adminkey}")
            logging.debug(f"🧠 Erwarteter Benutzer-pubkey_hex: {keys['pubkey_hex']}")
            logging.debug(f"📅 created_at: {created_at}")
            logging.debug("=" * 80 + "\n")
        
            pairing_link, actual_nwc_pubkey = create_nwc_key(
                username=username,
                wallet_id=wallet_id,
                created_at=created_at,
                lnbits_url=LNBits_API_BASE,
                session=session,
                user_api_key=adminkey
            )
        
            if actual_nwc_pubkey:
                if actual_nwc_pubkey != keys["pubkey_hex"]:
                    logging.warning("⚠️ Pubkey unterscheidet sich vom Benutzerpubkey!")
                    logging.warning(f"    Erwartet: {keys['pubkey_hex']}")
                    logging.warning(f"    Tatsächlich: {actual_nwc_pubkey}")
        
            # Finaler Link mit tatsächlichem Pubkey (aus Pairing)
            nwc_url = build_nwc_link(actual_nwc_pubkey or nwc_pubkey, secret)
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
                    "nwc_secret": secret,
                    "nwc_link": nwc_url,
                    "nwc_pubkey_actual": actual_nwc_pubkey or nwc_pubkey,
                    "lnurlp_link": lnurlp_link,
                    "lndhub_admin_url": lndhub_url
                }
            }
        
        except Exception as e:
            logging.exception(f"❌ Ausnahme bei der Erstellung von {username}:")
            return None

def load_existing_usernames():
    if not CSV_ACCOUNTS.exists(): return set()
    with open(CSV_ACCOUNTS, "r", newline="") as f:
        return {row["username"] for row in csv.DictReader(f)}

def load_mnemonic_map():
    if not CSV_KEYSOURCE.exists(): return {}
    with open(CSV_KEYSOURCE, "r", newline="") as f:
        reader = csv.DictReader(f)
        return {row["username"]: row["mnemonic"] for row in reader if row.get("mnemonic")}

def is_empty(fp): return not fp.exists() or fp.stat().st_size == 0

if __name__ == "__main__":
    print("Modus auswählen:")
    print("  1 = Benutzer manuell eingeben")
    print("  2 = 3 zufällige Benutzernamen generieren")
    print("  3 = Benutzer + Mnemonics aus CSV-Datei laden")
    mode = input("❓ Auswahl [1/2/3]: ").strip()

    usernames = []
    mnemonic_map = {}

    if mode == "2":
        usernames = [random_string(8) for _ in range(3)]

    elif mode == "3":
        csv_file = input(f"📂 CSV-Dateiname eingeben (z.B. {CSV_KEYSOURCE.name}): ").strip()
        csv_path = Path(csv_file)
        if not csv_path.exists():
            logging.critical(f"❌ CSV-Datei nicht gefunden: {csv_file}")
            exit(1)
        with open(csv_path, "r", newline="") as f:
            reader = csv.DictReader(f, delimiter=';')
            for row in reader:
                if row.get("username") and row.get("mnemonic"):
                    usernames.append(row["username"])
                    mnemonic_map[row["username"]] = row["mnemonic"]
        logging.info(f"📄 {len(usernames)} Benutzer aus {csv_file} geladen.")

    else:
        usernames = input("📝 Bitte Benutzernamen mit Leerzeichen eingeben: ").split()

    if not usernames:
        logging.error("❌ Keine Benutzernamen vorhanden.")
        exit(1)

    nostr_pubkey_hex = input("🔑 Optional: Nostr Public Key (Hex, leer lassen für Auto-Generierung): ").strip() or None

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
            "nwc_secret", "nwc_link", "nwc_pubkey_actual",  # NEU
            "lnurlp_link", "lndhub_admin_url"
        ])

        if is_empty(CSV_ACCOUNTS): acc.writeheader()
        if is_empty(CSV_WALLETS): wal.writeheader()
        if is_empty(CSV_SECRETS): sec.writeheader()

        for name in usernames:
            if name in existing:
                logging.info(f"⏩ Benutzer {name} übersprungen (bereits vorhanden).")
                continue
            mnemonic = mnemonic_map.get(name)
            result = create_user(name, mnemonic, nostr_pubkey_hex)
            if result:
                acc.writerow(result["account"])
                wal.writerow(result["wallet"])
                sec.writerow(result["secret"])
                logging.info(f"✅ Benutzer {name} erfolgreich erstellt.")