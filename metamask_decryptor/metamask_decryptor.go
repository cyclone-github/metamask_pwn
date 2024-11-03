package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

/*
Cyclone's Metamask Vault Decryptor
POC tool to decrypt metamask vault wallets
This tool is proudly the first publicly released Metamask Vault decryptor / cracker to support the new Metamask wallet vaults which have a dynamic iteration
Tool will be superseded by hashcat once a custom hashcat kernel is released
coded by cyclone in Go

GNU General Public License v2.0
https://github.com/cyclone-github/metamask_pwn/blob/main/LICENSE

version history
v0.1.0-2024-02-27; initial github release
v0.2.0-2024-02-29
    in reference to https://github.com/cyclone-github/metamask_decryptor/issues/1
	added multi-threading support
	added stats printout
v0.2.1-2024-03-19
	fixed https://github.com/cyclone-github/metamask_decryptor/issues/2
	added support for decrypting vaults linked to a hardware wallet
v0.2.2-2024-11-03
	updated github repository url, https://github.com/cyclone-github/metamask_pwn/

TO-DO:
	add ETA
	add wordlist progress bar
    cleanup and refactor code
*/

// clear screen function
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
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Metamask Vault Decryptor v0.2.2-2024-11-03\nhttps://github.com/cyclone-github/metamask_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Supports both old and new Metamask vaults with or without 'KeyMetadata'

Example vaults supported:
	- Old vault format: {"data": "","iv": "","salt": ""}
	- New vault format: {"data": "","iv": "","keyMetadata": {"algorithm": "PBKDF2","params": {"iterations": }},"salt": ""}

Example Usage:
./metamask_decryptor.bin -h {wallet_json} -w {wordlist} -t {optional: cpu threads} -s {optional: print status every nth sec}

./metamask_decryptor.bin -h metamask.txt -w wordlist.txt -t 16 -s 10`
	fmt.Fprintln(os.Stderr, str)
}

// MetamaskVault vault struct
type MetamaskVault struct {
	Data        string       `json:"data"`
	Iv          string       `json:"iv"`
	Salt        string       `json:"salt"`
	KeyMetadata *KeyMetadata `json:"keyMetadata,omitempty"`
	Decrypted   bool         `json:"-"`
}

// KeyMetadata struct (newer metamask vaults)
type KeyMetadata struct {
	Algorithm string    `json:"algorithm"`
	Params    KeyParams `json:"params"`
}

// PBKDF2 parameters (newer metamask vaults)
type KeyParams struct {
	Iterations int `json:"iterations"`
}

// Vault struct (for seed key)
type Vault struct {
	Type string `json:"type"`
	Data struct {
		Mnemonic interface{} `json:"mnemonic"` // seed phrase can be a string or array of numbers
	} `json:"data"`
}

// decrypt metamask vault
func decryptVault(password string, vault *MetamaskVault) bool {
	salt, _ := base64.StdEncoding.DecodeString(vault.Salt)
	iterations := 10000 // default iterations for v1 vaults
	if vault.KeyMetadata != nil {
		iterations = vault.KeyMetadata.Params.Iterations // use custom iterations from vault metadata for v2 vaults
	}

	key := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}

	iv, _ := base64.StdEncoding.DecodeString(vault.Iv)
	data, _ := base64.StdEncoding.DecodeString(vault.Data)
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return false
	}

	decryptedData, err := gcm.Open(nil, iv, data, nil)
	if err != nil {
		return false
	}

	var vaultData []Vault
	if err := json.Unmarshal(decryptedData, &vaultData); err != nil {
		// if json unmarshal fails, use regex to find mnemonic in decrypted data
		regex := regexp.MustCompile(`"mnemonic":"([^"]+)"`)
		matches := regex.FindStringSubmatch(string(decryptedData))
		if len(matches) > 1 {
			fmt.Printf("\nDecrypted Vault: '%.64s...'\nSeed Phrase:\t'%s'\nVault Password: '%s'\n", fmt.Sprintf("%v", *vault), matches[1], password)
		} else { // if regex also fails to find mnemonic in decrypted data, print entire decrypted string
			fmt.Printf("\nDecryption successful but JSON unmarshaling failed\nDecrypted String: '%s...'\nVault Password: '%s'\n", string(decryptedData), password)
		}
		return true
	}

	for _, v := range vaultData {
		mnemonic, isString := v.Data.Mnemonic.(string)
		if isString {
			if len(mnemonic) > 0 {
				fmt.Printf("\nDecrypted Vault: '%.64s...'\nSeed Phrase:\t'%s'\nVault Password:\t'%s'\n", fmt.Sprintf("%v", *vault), mnemonic, password)
				return true
			}
		} else if mnemonicSlice, isArray := v.Data.Mnemonic.([]interface{}); isArray {
			mnemonicStr := make([]byte, len(mnemonicSlice))
			for i, val := range mnemonicSlice {
				mnemonicStr[i] = byte(val.(float64))
			}
			if len(mnemonicStr) > 0 {
				fmt.Printf("\nDecrypted Vault: '%.64s...'\nSeed Phrase:\t'%s'\nVault Password:\t'%s'\n", fmt.Sprintf("%v", *vault), string(mnemonicStr), password)
				return true
			}
		}
	}
	return false
}

// parse metamask json
func ReadMetamaskJSON(filePath string) ([]MetamaskVault, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	uniqueVaults := make(map[string]MetamaskVault)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		originalLine := scanner.Text()
		line := strings.TrimSpace(originalLine)
		line = strings.Replace(line, "\\", "", -1)

		if line == "" {
			continue
		}

		var vault MetamaskVault
		if err := json.Unmarshal([]byte(line), &vault); err != nil {
			// skip invalid json strings
			continue
		}

		// store vaults into map to deduplicate
		key := vault.Data + ":" + vault.Iv + ":" + vault.Salt
		uniqueVaults[key] = vault
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var dedupedVaults []MetamaskVault
	for _, vault := range uniqueVaults {
		dedupedVaults = append(dedupedVaults, vault)
	}

	return dedupedVaults, nil
}

// print welcome screen
func printWelcomeScreen(vaultFileFlag, wordlistFileFlag *string, validVaultCount, numThreads int) {
	fmt.Fprintln(os.Stderr, " ------------------------------------ ")
	fmt.Fprintln(os.Stderr, "| Cyclone's Metamask Vault Decryptor |")
	fmt.Fprintln(os.Stderr, " ------------------------------------ ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Vault file:\t%s\n", *vaultFileFlag)
	fmt.Fprintf(os.Stderr, "Valid Vaults:\t%d\n", validVaultCount)
	fmt.Fprintf(os.Stderr, "CPU Threads:\t%d\n", numThreads)
	fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	fmt.Fprintln(os.Stderr, "Working...")
}

// hash cracking worker
func startWorker(ch <-chan string, stopChan chan struct{}, vaults []MetamaskVault, crackedCountCh chan int, linesProcessedCh chan int) {
	for {
		select {
		case <-stopChan:
			// stop if channel is closed
			return
		case password, ok := <-ch:
			if !ok {
				time.Sleep(100 * time.Millisecond)
				close(stopChan) // channel closed, no more passwords to process
				return
			}
			allDecrypted := true
			for i, vault := range vaults {
				if !vault.Decrypted { // only check for undecrypted vaults
					if decryptVault(password, &vaults[i]) {
						crackedCountCh <- 1
						// mark vault as decrypted
						vaults[i].Decrypted = true
					} else {
						allDecrypted = false
					}
				}
			}
			linesProcessedCh <- 1

			// check if all vaults are decrypted
			if allDecrypted {
				// close stop channel to signal all workers to stop
				select {
				case <-stopChan:
					// channel already closed, do nothing
				default:
					// close stop channel to signal all workers to stop
					close(stopChan)
				}
				return // Exit the goroutine.
			}
		}
	}
}

// set CPU threads
func setNumThreads(userThreads int) int {
	if userThreads <= 0 || userThreads > runtime.NumCPU() {
		return runtime.NumCPU()
	}
	return userThreads
}

// goroutine to watch for ctrl+c
func handleGracefulShutdown(stopChan chan struct{}) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interruptChan
		fmt.Fprintln(os.Stderr, "\nCtrl+C pressed. Shutting down...")
		close(stopChan)
	}()
}

// monitor status
func monitorPrintStats(crackedCountCh, linesProcessedCh <-chan int, stopChan <-chan struct{}, startTime time.Time, validVaultCount int, wg *sync.WaitGroup, interval int) {
	crackedCount := 0
	linesProcessed := 0
	var ticker *time.Ticker
	if interval > 0 {
		ticker = time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
	}

	for {
		select {
		case <-crackedCountCh:
			crackedCount++
		case <-linesProcessedCh:
			linesProcessed++
		case <-stopChan:
			// print final stats and exit
			printStats(time.Since(startTime), crackedCount, validVaultCount, linesProcessed, true)
			wg.Done()
			return
		case <-func() <-chan time.Time {
			if ticker != nil {
				return ticker.C
			}
			// return nil channel if ticker is not used
			return nil
		}():
			if interval > 0 {
				printStats(time.Since(startTime), crackedCount, validVaultCount, linesProcessed, false)
			}
		}
	}
}

// printStats
func printStats(elapsedTime time.Duration, crackedCount, validVaultCount, linesProcessed int, exitProgram bool) {
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	linesPerSecond := float64(linesProcessed) / elapsedTime.Seconds()
	fmt.Fprintf(os.Stderr, "\nDecrypted: %d/%d", crackedCount, validVaultCount)
	fmt.Fprintf(os.Stderr, "\t%.2f h/s", linesPerSecond)
	fmt.Fprintf(os.Stderr, "\t%02dh:%02dm:%02ds", hours, minutes, seconds)
	if exitProgram {
		fmt.Println("")
		os.Exit(0) // exit only if indicated by 'exitProgram' flag
	}
}

// main func
func main() {
	wordlistFileFlag := flag.String("w", "", "Wordlist file")
	vaultFileFlag := flag.String("h", "", "Vault file")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
	threadFlag := flag.Int("t", runtime.NumCPU(), "CPU threads to use (optional)")
	statsIntervalFlag := flag.Int("s", 60, "Interval in seconds for printing stats. Defaults to 60.")
	flag.Parse()

	clearScreen()

	// run sanity checks for special flags
	if *versionFlag {
		versionFunc()
		os.Exit(0)
	}
	if *cycloneFlag {
		line := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		str, _ := base64.StdEncoding.DecodeString(line)
		fmt.Println(string(str))
		os.Exit(0)
	}
	if *helpFlag {
		helpFunc()
		os.Exit(0)
	}

	if *wordlistFileFlag == "" || *vaultFileFlag == "" {
		fmt.Fprintln(os.Stderr, "Both -w (wordlist file) and -h (vault file) flags are required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	startTime := time.Now()

	// set CPU threads
	numThreads := setNumThreads(*threadFlag)

	// channels / variables
	crackedCountCh := make(chan int)
	linesProcessedCh := make(chan int)
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	// goroutine to watch for ctrl+c
	handleGracefulShutdown(stopChan)

	// read vaults
	vaults, err := ReadMetamaskJSON(*vaultFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading vault file:", err)
		os.Exit(1)
	}
	validVaultCount := len(vaults)

	// print welcome screen
	printWelcomeScreen(vaultFileFlag, wordlistFileFlag, validVaultCount, numThreads)

	// create channel for each worker goroutine
	workerChannels := make([]chan string, numThreads)
	for i := range workerChannels {
		workerChannels[i] = make(chan string, 1000) // buffer size
	}

	// start worker goroutines
	for _, ch := range workerChannels {
		wg.Add(1)
		go func(ch <-chan string) {
			defer wg.Done()
			startWorker(ch, stopChan, vaults, crackedCountCh, linesProcessedCh)
		}(ch)
	}

	// reader goroutine
	wg.Add(1)
	go func() {
		defer func() {
			for _, ch := range workerChannels {
				close(ch) // close all worker channels when done
				return
			}
		}()
		defer wg.Done()

		wordlistFile, err := os.Open(*wordlistFileFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error opening wordlist file:", err)
			return
		}
		defer wordlistFile.Close()

		scanner := bufio.NewScanner(wordlistFile)
		workerIndex := 0
		for scanner.Scan() {
			word := strings.TrimRight(scanner.Text(), "\n")
			workerChannels[workerIndex] <- word
			workerIndex = (workerIndex + 1) % len(workerChannels) // round-robin
		}
	}()

	// monitor status of workers
	wg.Add(1)
	go monitorPrintStats(crackedCountCh, linesProcessedCh, stopChan, startTime, validVaultCount, &wg, *statsIntervalFlag)

	wg.Wait() // wait for all goroutines to finish
}

// end code
