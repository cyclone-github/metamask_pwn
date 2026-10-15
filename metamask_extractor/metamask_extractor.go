package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

/*
Cyclone's Metamask Vault Hash Extractor
Tool to extract metamask vault data & hashcat compatible hash from Metamask Vault
https://github.com/cyclone-github/metamask_pwn

Metamask Vault location for Chrome extensions:
Linux: /home/$USER/.config/google-chrome/Default/Local\ Extension\ Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/
Mac: Library>Application Support>Google>Chrome>Default>Local Extension Settings>nkbihfbeogaeaoehlefnkodbefgpgknn
Windows: C:\Users\$USER\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn

Credits:
https://support.metamask.io/hc/en-us/articles/360018766351-How-to-use-the-Vault-Decryptor-with-the-MetaMask-Vault-Data
https://btcrecover.readthedocs.io/en/latest/Extract_Scripts/#usage-for-metamask
My own methods for extracting metamask hashes and JSON data
coded by cyclone in Go

GNU General Public License v2.0
https://github.com/cyclone-github/metamask_pwn/blob/main/LICENSE

version history
v0.1.1; initial github release
v0.2.0-2024-03-01
	fixed https://github.com/cyclone-github/metamask_extractor/issues/1
	added support for new vault format with dynamic iterations
	dropped "-input" flag
	updated code and printouts
v0.2.1-2024-03-02
	updated URL for hashcat 26620 kernel
v0.2.2-2024-11-03
	updated github repository url, https://github.com/cyclone-github/metamask_pwn/
v0.3.0-2026-10-15
	remove clear screen
	improved vault extraction for nested Chrome JSON
	open LevelDB read-only without .ldb check
*/

// version func
func printVersion() {
	fmt.Fprintln(os.Stderr, "Cyclone's Metamask Vault Extractor v0.3.0-2026-10-15\nhttps://github.com/cyclone-github/metamask_pwn")
	fmt.Fprintln(os.Stderr)
}

// help func
func printHelp() {
	printVersion()
	str := `Supports both old and new Metamask vaults with or without 'KeyMetadata'

Example vaults supported:
	- Old vault format: {"data": "","iv": "","salt": ""}
	- New vault format: {"data": "","iv": "","keyMetadata": {"algorithm": "PBKDF2","params": {"iterations": }},"salt": ""}

Example Usage:
./metamask_extractor.bin [-version] [-help] [metamask_vault_dir]
./metamask_extractor.bin nkbihfbeogaeaoehlefnkodbefgpgknn/`
	fmt.Fprintln(os.Stderr, str)
}

// metamask vault json struct (support OLD and NEW vaults)
type Hash struct {
	Salt        string `json:"salt"`
	Iv          string `json:"iv"`
	VaultData   string `json:"data"`
	KeyMetadata *struct {
		Algorithm string `json:"algorithm"`
		Params    struct {
			Iterations int `json:"iterations"`
		} `json:"params"`
	} `json:"keyMetadata,omitempty"`
}

// main func
func main() {
	versionFlag := flag.Bool("version", false, "Print program version")
	cycloneFlag := flag.Bool("cyclone", false, "")
	helpFlag := flag.Bool("help", false, "Print usage information")
	flag.Parse()

	if *versionFlag {
		printVersion()
		return
	}

	if *cycloneFlag {
		line := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		str, _ := base64.StdEncoding.DecodeString(line)
		fmt.Println(string(str))
		os.Exit(0)
	}

	if *helpFlag {
		printHelp()
		return
	}

	ldbDir := flag.Arg(0)

	// sanity check: make sure metamask vault dir is provided in CLI arg
	if ldbDir == "" {
		fmt.Fprintln(os.Stderr, "Error: MetaMask vault directory is required")
		printHelp()
		os.Exit(1)
	}

	info, err := os.Stat(ldbDir)
	if err != nil || !info.IsDir() {
		fmt.Fprintln(os.Stderr, "Error: Provided path does not exist or is not a directory")
		os.Exit(1)
	}

	// open LevelDB database
	db, err := leveldb.OpenFile(ldbDir, &opt.Options{
		ErrorIfMissing: true,
		ReadOnly:       true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open Vault:", err)
		os.Exit(1)
	}
	defer db.Close()

	var currentData bool

	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		value := iter.Value()

		jsonData, ok := extractJSONData(value)
		if !ok {
			continue
		}

		if currentData {
			fmt.Println()
		} else {
			currentData = true
			fmt.Println(" ----------------------------------------------------- ")
			fmt.Println("|        Cyclone's Metamask Vault Hash Extractor       |")
			fmt.Println("|  Use Metamask Vault Decryptor to decrypt JSON below  |")
			fmt.Println("|    https://github.com/cyclone-github/metamask_pwn    |")
			fmt.Println(" ----------------------------------------------------- ")
		}

		fmt.Println(jsonData) // print extracted JSON data

		var h Hash
		if err := json.Unmarshal([]byte(jsonData), &h); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal JSON: %v\n", err)
			continue
		}

		// print Metamask hash string based on format (OLD or NEW)
		var metamaskHash string
		if h.KeyMetadata != nil {
			// NEW format with iteration count
			// this may need updated once hashcat releases offical support for this new algo
			metamaskHash = fmt.Sprintf("$metamask$%d$%s$%s$%s", h.KeyMetadata.Params.Iterations, h.Salt, h.Iv, h.VaultData)
			fmt.Println(" -------------------------------------------------------- ")
			fmt.Println("|           hashcat -m 26620 hash (NEW format)           |")
			fmt.Println("| https://github.com/cyclone-github/hashcat_26620_kernel |")
			fmt.Println(" -------------------------------------------------------- ")
		} else {
			// OLD format without iteration count
			metamaskHash = fmt.Sprintf("$metamask$%s$%s$%s", h.Salt, h.Iv, h.VaultData)
			fmt.Println(" -------------------------------------------------- ")
			fmt.Println("|        hashcat -m 26600 hash (OLD format)        |")
			fmt.Println(" -------------------------------------------------- ")
		}
		fmt.Println(metamaskHash)
	}
	if err := iter.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to iterate Vault: %v\n", err)
	}
}

// json extractor helper function
func extractJSONData(value []byte) (string, bool) {
	return findVaultJSON(value, 0)
}

func findVaultJSON(raw []byte, depth int) (string, bool) {
	if depth > 12 {
		return "", false
	}

	var h Hash
	if json.Unmarshal(raw, &h) == nil &&
		h.VaultData != "" && h.Iv != "" && h.Salt != "" {
		return string(raw), true
	}

	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		if vault, ok := obj["vault"]; ok {
			if result, ok := findVaultJSON(vault, depth+1); ok {
				return result, true
			}
		}

		for _, nested := range obj {
			if result, ok := findVaultJSON(nested, depth+1); ok {
				return result, true
			}
		}
	}

	var encoded string
	if json.Unmarshal(raw, &encoded) == nil {
		return findVaultJSON([]byte(encoded), depth+1)
	}

	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		for _, nested := range arr {
			if result, ok := findVaultJSON(nested, depth+1); ok {
				return result, true
			}
		}
	}

	return "", false
}

// end code
