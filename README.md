[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=metamask_pwn&theme=gruvbox)](https://github.com/cyclone-github/metamask_pwn/)

[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/metamask_pwn.svg)](https://github.com/cyclone-github/metamask_pwn/issues)
[![License](https://img.shields.io/github/license/cyclone-github/metamask_pwn.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/metamask_pwn.svg)](https://github.com/cyclone-github/metamask_pwn/releases)

# metamask_pwn
Toolset to extract and decrypt metamask vaults (wallets)
- Contact me at https://forum.hashpwn.net/user/cyclone if you need help recovering your Metamask wallet password or seed phrase

# Metamask Vault Hash Extractor
Tool to extract metamask vaults to JSON and hashcat compatible formats

### Info:
- Metamask JSON vaults can be decrypted with https://github.com/cyclone-github/metamask_pwn
- Previous Metamask hashes can be cracked using hashcat -m 26600
- New Metamask hashes can be cracked with hashcat using the custom -m 26620 kernel below
  - https://github.com/cyclone-github/hashcat_26620_kernel

### Metamask Vault location for Chrome extensions:
- Linux: `/home/$USER/.config/google-chrome/Default/Local\ Extension\ Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/`
- Mac: `Library>Application Support>Google>Chrome>Default>Local Extension Settings>nkbihfbeogaeaoehlefnkodbefgpgknn`
- Windows `C:\Users\$USER\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn`

### Usage:
- Linux: `./metamask_extractor.bin {metamask_vault_dir}`
- Windows: `metamask_extractor.exe {metamask_vault_dir}`

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/metamask_pwn.git`
  - `cd metamask_pwn`
  - `cd metamask_extractor`
  - `go mod init metamask_extractor`
  - `go mod tidy`
  - `go build -ldflags="-s -w" metamask_extractor.go`
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt

# Metamask Vault Decryptor
### POC tool to decrypt metamask vault wallets
_**This tool is proudly the first publicly released Metamask Vault decryptor / cracker to support the new Metamask wallet vaults which have a dynamic iteration.**_
```
./metamask_decryptor_amd64.bin -h metamask_json.txt -w wordlist.txt
 ------------------------------------ 
| Cyclone's Metamask Vault Decryptor |
 ------------------------------------ 

Vault file:     metamask_json.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
Working...

Decrypted: 0/1  5430.89 h/s     00h:01m:00s
```
### Info:
- Supports previous Metamask vaults as well as new vaults with "KeyMetadata" which have dynamic iterations
- If you need help extracting Metamask vaults, use `Metamask Extractor` https://github.com/cyclone-github/metamask_pwn
- _`Metamask Vault Decryptor` is superseded by hashcat, however, `Metamask Vault Decryptor` also displays the seed phrase alongside the vault password, which hashcat does not currently support_

### Example vaults supported:
- Old vault format: `{"data": "","iv": "","salt": ""}`
- New vault format: `{"data": "","iv": "","keyMetadata": {"algorithm": "PBKDF2","params": {"iterations": }},"salt": ""}`

### Usage example:
- `./metamask_decryptor.bin -h {wallet_json} -w {wordlist}`

### Output example:
If the tool successfully decrypts the vault, tool will print the vault json, seed phrase and vault password
```
Decrypted Vault: '{}'
Seed Phrase:    ''
Vault Password: ''
```

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/metamask_pwn.git`
  - `cd metamask_pwn`
  - `cd metamask_decryptor`
  - `go mod init metamask_decryptor`
  - `go mod tidy`
  - `go build -ldflags="-s -w" metamask_decryptor.go`
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
