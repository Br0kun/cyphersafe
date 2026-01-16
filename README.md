                                                    
                                                                              
                                                                              
                                                                              
                                                                                                                                                    
````md
# cyphersafe (C)

A small terminal password manager written in C.  
It uses a per-user master password (SHA-256) and a simple XOR layer to store entries in a local file. Some actions require a “private key” check derived from the user hash. The program also includes alert/honeypot notifications (Telegram) for suspicious actions.

## Features
- Multi-user login (each user has their own config and password store)
- Master password hashing with SHA-256 (OpenSSL)
- Private key verification before sensitive actions (view/delete)
- Store credentials locally in an encrypted line format (XOR with key derived from SHA-256)
- Add / View / Delete saved passwords
- Password generator
- Basic terminal colors and menu UI
- Alerts + honeypot triggers (Telegram via curl)

## How it works (quick)
- First run for a username:
  - You set a master password
  - The program hashes it (SHA-256) and saves it to: `username.cfg`
  - It prints a “private key” (hex of the hash). Keep it safe.
- Saved passwords are stored in: `username_pwds.txt`
  - Each line is: `platform|email|password` then XOR-encrypted using the derived key
- Viewing/deleting passwords requires the private key check.

## Files created
- `USERNAME.cfg`  
  Binary file containing 32 bytes (SHA-256 hash of the master password)
- `USERNAME_pwds.txt`  
  Text file containing XOR-encrypted entries (one line per password)

## Build
Requires OpenSSL development libraries.

Linux:
```bash
gcc main.c -o securepass -lssl -lcrypto
````

Windows (MinGW example):

```bash
gcc main.c -o securepass.exe -lssl -lcrypto
```

## Run

```bash
./securepass
```

## Notes

* XOR is used here for learning/demo purposes. It is not strong encryption.
* Telegram alerts use `curl` commands inside the code. If curl is missing, alerts will fail silently.
* Keep your private key and master password secret. Anyone with them can decrypt stored lines.

## Author

Br0k

```
```
