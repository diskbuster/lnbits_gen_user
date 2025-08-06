LNbits User Creation Script

This script automates the creation of LNbits user accounts via the LNbits API. It generates users, wallets, Nostr keys, and NWC (Nostr Wallet Connect) connections — exactly as if they were created manually through the LNbits UI.
The script supports full .csv export and structured debug logging.

⸻

✨ Features
	•	Create users via LNbits API
	•	Generate and store wallets, admin keys, and invoices keys
	•	Generate deterministic Nostr keys (or import existing ones)
	•	Generate correct NWC connections with secrets and internal pubkeys
	•	Export users, wallets, secrets to .csv
	•	Skip users if already created
	•	Load optional .csv input with predefined usernames and mnemonics
	•	Fully configurable via .env file

 
