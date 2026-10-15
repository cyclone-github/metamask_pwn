[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=metamask_pwn&theme=gruvbox)](https://github.com/cyclone-github/metamask_pwn/)

[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/metamask_pwn.svg)](https://github.com/cyclone-github/metamask_pwn/issues)
[![License](https://img.shields.io/github/license/cyclone-github/metamask_pwn.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/metamask_pwn.svg)](https://github.com/cyclone-github/metamask_pwn/releases)

# metamask_pwn
Toolset to extract and decrypt metamask vaults (wallets)
- Contact me at [https://forum.hashpwn.net/user/cyclone](https://forum.hashpwn.net/user/cyclone) if you need help recovering your Metamask wallet password or seed phrase

### Install metamask_extractor:
```
go install github.com/cyclone-github/metamask_pwn/metamask_extractor@main
```
### Install metamask_decryptor:
```
go install github.com/cyclone-github/metamask_pwn/metamask_decryptor@main
```

# Metamask Vault Hash Extractor
Tool to extract metamask vaults to JSON and hashcat compatible formats

### Info:
- Metamask JSON vaults can be decrypted with [https://github.com/cyclone-github/metamask_pwn](https://github.com/cyclone-github/metamask_pwn)
- Previous Metamask hashes can be cracked using hashcat -m 26600
- New Metamask hashes can be cracked with hashcat using my custom -m 26620 kernel below
  - [https://github.com/cyclone-github/hashcat_26620_kernel](https://github.com/cyclone-github/hashcat_26620_kernel)
- Note: metamask_extractor supports hashcat mode 26620 for convenience, but this is a third-party module written by cyclone that is not affiliated with or included in the official hashcat beta or release builds at [https://github.com/hashcat/hashcat](https://github.com/hashcat/hashcat)
- Improved extraction of nested and escaped vault JSON from Chrome/Brave LevelDB, including databases using `.sst` files

### Metamask Vault location for Chrome extensions:
- Linux: `/home/$USER/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/`
- Mac: `~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/`
- Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\`

### Metamask Vault location for Brave extensions:
- Linux: `/home/$USER/.config/BraveSoftware/Brave-Browser/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/`
- Mac: `~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/`
- Windows: `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\`

**Note:** For additional browser profiles, replace `Default` with `Profile 1`, `Profile 2`, etc. The active profile directory can be identified using `chrome://version` or `brave://version`.

### Usage:
- Linux: `./metamask_extractor.bin {metamask_vault_dir}`
- Windows: `metamask_extractor.exe {metamask_vault_dir}`

**CLI flags:**

| Flag / argument | Description |
| --- | --- |
| `{metamask_vault_dir}` | Required positional argument: MetaMask extension LevelDB directory |
| `-version` | Print program version |
| `-help` | Print usage information |

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/metamask_pwn.git`  # clone repo
  - `cd metamask_pwn/metamask_extractor`                            # enter project directory
  - `go mod init metamask_extractor`                                # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                                   # download dependencies
  - `go build -ldflags="-s -w" .`                                   # compile binary in current directory
  - `go install -ldflags="-s -w" .`                                 # compile binary and install to $GOPATH
- Compile from source code how-to:
  - [https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt](https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt)

# Metamask Vault Decryptor
### Tool to decrypt metamask vault wallets
**This tool is proudly the first publicly released Metamask Vault decryptor / cracker to support the new Metamask wallet vaults which have a dynamic iteration.**
```
./metamask_decryptor.bin -h metamask_json.txt -w wordlist.txt -r cyclone_250.rule
 ------------------------------------
| Cyclone's Metamask Vault Decryptor |
 ------------------------------------

Vault file:     metamask_json.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
Rules:          cyclone_250.rule (250)
Working...

Decrypted: 0/1  6530.83 h/s     00h:01m:00s
```
### Info:
- Supports previous Metamask vaults as well as new vaults with "KeyMetadata" which have dynamic iterations
- Supports hashcat-style rules using `-r` flag.
- If you need help extracting Metamask vaults, use `Metamask Extractor` [https://github.com/cyclone-github/metamask_pwn](https://github.com/cyclone-github/metamask_pwn)
- *`Metamask Vault Decryptor` is superseded by hashcat, however, `Metamask Vault Decryptor` also displays the seed phrase alongside the vault password, which hashcat does not support*

### Example vaults supported:
- Old vault format: `{"data": "","iv": "","salt": ""}`
- New vault format: `{"data": "","iv": "","keyMetadata": {"algorithm": "PBKDF2","params": {"iterations": }},"salt": ""}`

### Usage example:
- `./metamask_decryptor.bin -h {wallet_json} -w {wordlist}`
- `./metamask_decryptor.bin -h metamask_json.txt -w wordlist.txt -r cyclone_250.rule -t 16 -s 10`

**CLI flags:**

| Flag | Description |
| --- | --- |
| `-h` | Vault JSON file (required) |
| `-w` | Wordlist file (required) |
| `-r` | Rules file (optional) |
| `-t` | CPU threads / workers (default: available CPUs) |
| `-s` | Stats interval in seconds (default: 60; `0` disables periodic stats) |
| `-version` | Print program version |
| `-help` | Print usage information |

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
  - `git clone https://github.com/cyclone-github/metamask_pwn.git`  # clone repo
  - `cd metamask_pwn/metamask_decryptor`                            # enter project directory
  - `go mod init metamask_decryptor`                                # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                                   # download dependencies
  - `go build -ldflags="-s -w" .`                                   # compile binary in current directory
  - `go install -ldflags="-s -w" .`                                 # compile binary and install to $GOPATH
- Compile from source code how-to:
  - [https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt](https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt)