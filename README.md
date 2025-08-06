# LNbits User Creation Script

This script allows you to **automatically create LNbits users** with optional Nostr keys, LNURLp payment links, LNDHub admin URLs, and NWC (Nostr Wallet Connect) connections — just like using the LNbits UI.

Usecase could be for fast onboarding peers of people with premined nostr identitys and associated wallets. therefore a secrets.csv will be created with all needed onboading information to connect via different clients.

 

---

## ✨ Features

- Automatically creates:
  - LNbits user accounts and wallets
  - Nostr keypairs (or uses custom ones)
  - LNURLp payment links with Zap support
  - NIP-05 public identities (`npub@yourdomain`)
  - LNDHub admin links
  - NWC wallet connection links using Nostr key derivation (secp256k1)

- Stores everything in 3 structured CSV files:
  - `lnbits_accounts.csv`
  - `lnbits_wallets.csv`
  - `lnbits_secrets.csv`

- Supports three modes:
  - Manual username entry
  - Auto-generate random usernames
  - Load usernames and mnemonics from CSV

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/lnbits_gen_user.git
cd lnbits_gen_user
```

### 2. Create a virtual environment (optional but recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install required dependencies

```bash
pip install -r requirements.txt
```

### 4. Create a `.env` configuration file

```bash
cp .env.example .env
```

Then edit `.env` with your own values:

```env
LNBITS_API_BASE=https://lnbits.yourdomain.com
LNBITS_ADMIN_USERNAME=admin
LNBITS_ADMIN_PASSWORD=secretpassword
DOMAIN=yourdomain.com
DOMAIN_ID=your_nip05_domain_id
```

---

## 🚀 Usage

### Start the script

```bash
python3 make_user_en.py
```

### Choose a mode

You will be prompted to choose a mode:

1. **Manual** – enter one or more usernames
2. **Random** – generate 3 random usernames
3. **From CSV** – load usernames and optional mnemonics from a CSV file

You can optionally provide a **custom Nostr pubkey** (hex format), or leave blank to generate one.

---

## 📁 Output files

- `lnbits_accounts.csv` – LNbits user data
- `lnbits_wallets.csv` – wallet and key info
- `lnbits_secrets.csv` – Nostr keys, NWC, LNURLp, LNDHub
- `lnbits_user_creation.log` – full debug log of the session

---

## 📤 Git Ignore

The following files are excluded from version control via `.gitignore`:

```
.env
*.csv
lnbits_user_creation.log
make_user.py
```

---

## ✅ Tested With

- LNbits v1.1.0+
- NWCProvider extension
- Python 3.10+
- Ubuntu 20.04 / 22.04

---

## 🛠 Troubleshooting

- Make sure your `.env` has valid login credentials and API URL.
- Ensure all required LNbits extensions (`lnurlp`, `lndhub`, `nwcprovider`) are **installed and activated**.

---

## 📄 License

MIT License – see [LICENSE](LICENSE) file for details.