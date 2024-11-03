package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"

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
*/

// clear screen func
func clearScreen() {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

// version func
func printVersion() {
	fmt.Fprintln(os.Stderr, "Cyclone's Metamask Vault Extractor v0.2.2-2024-11-03\nhttps://github.com/cyclone-github/metamask_pwn\n")
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

	clearScreen()

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
	if os.IsNotExist(err) || !info.IsDir() {
		fmt.Fprintln(os.Stderr, "Error: Provided path does not exist or is not a directory")
		os.Exit(1)
	}

	// check if dir contains any .ldb files
	files, err := ioutil.ReadDir(ldbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read the directory: %v\n", err)
		os.Exit(1)
	}
	ldbFileFound := false
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".ldb") {
			ldbFileFound = true
			break
		}
	}
	if !ldbFileFound {
		fmt.Fprintln(os.Stderr, "Error: No .ldb files found in the provided directory. Please ensure you've specified the correct MetaMask vault directory.")
		os.Exit(1)
	}

	// open LevelDB database
	db, err := leveldb.OpenFile(ldbDir, &opt.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open Vault:", err)
		os.Exit(1)
	}
	defer db.Close()

	var currentData bool

	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		if bytes.Contains(key, []byte("data")) {
			dataStr := strings.ReplaceAll(string(value), "\\", "")
			if strings.Contains(dataStr, "salt") {
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

				jsonData, ok := extractJSONData(dataStr)
				if !ok {
					fmt.Fprintf(os.Stderr, "Failed to extract JSON data\n")
					continue
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
		}
	}
}

// json extractor helper function
func extractJSONData(value string) (string, bool) {
	dataStart := strings.Index(value, `{"data":"`)
	if dataStart == -1 {
		return "", false
	}
	braceCount := 1
	for i := dataStart + len(`{"data":"`); i < len(value); i++ {
		switch value[i] {
		case '{':
			braceCount++
		case '}':
			braceCount--
			if braceCount == 0 {
				return value[dataStart : i+1], true
			}
		}
	}
	return "", false
}

// end code
