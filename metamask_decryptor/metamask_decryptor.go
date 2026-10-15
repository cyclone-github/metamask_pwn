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
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

/*
Cyclone's Metamask Vault Decryptor
POC tool to decrypt metamask vault wallets
This tool is proudly the first publicly released Metamask Vault decryptor / cracker to support the new Metamask wallet vaults which have a dynamic iteration
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
v0.3.0-2026-10-15
	fixed https://github.com/cyclone-github/metamask_pwn/issues/1
	remove clear screen
	added rule support with -r
	added candidate deduplication when using -r
	fixed scanner errors and EOF shutdown
	updated h/s to count PBKDF2 attempts

TO-DO:
	add ETA
	add wordlist progress bar
	cleanup and refactor code
*/

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Metamask Vault Decryptor v0.3.0-2026-10-15\nhttps://github.com/cyclone-github/metamask_pwn")
	fmt.Fprintln(os.Stderr)
}

// help func
func helpFunc() {
	versionFunc()
	str := `Supports both old and new Metamask vaults with or without 'KeyMetadata'

Example vaults supported:
	- Old vault format: {"data": "","iv": "","salt": ""}
	- New vault format: {"data": "","iv": "","keyMetadata": {"algorithm": "PBKDF2","params": {"iterations": }},"salt": ""}

Example Usage:
./metamask_decryptor.bin -h {wallet_json} -w {wordlist} -r {rules} -t {cpu threads} -s {print status every nth sec}

./metamask_decryptor.bin -h metamask.txt -w wordlist.txt -r cyclone_250.rule -t 16 -s 10`
	fmt.Fprintln(os.Stderr, str)
}

// MetamaskVault vault struct
type MetamaskVault struct {
	Data        string       `json:"data"`
	Iv          string       `json:"iv"`
	Salt        string       `json:"salt"`
	KeyMetadata *KeyMetadata `json:"keyMetadata,omitempty"`
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

// decoded vault data shared by workers (read-only during cracking)
type preparedVault struct {
	Vault      MetamaskVault
	Salt       []byte
	Iv         []byte
	Data       []byte
	Iterations int
	Decrypted  atomic.Bool
}

// decode vault once instead of decoding base64 for every password
func prepareVaults(vaults []MetamaskVault) ([]*preparedVault, error) {
	prepared := make([]*preparedVault, 0, len(vaults))
	for _, vault := range vaults {
		salt, err := base64.StdEncoding.DecodeString(vault.Salt)
		if err != nil {
			return nil, fmt.Errorf("invalid vault salt: %w", err)
		}
		iv, err := base64.StdEncoding.DecodeString(vault.Iv)
		if err != nil {
			return nil, fmt.Errorf("invalid vault iv: %w", err)
		}
		data, err := base64.StdEncoding.DecodeString(vault.Data)
		if err != nil {
			return nil, fmt.Errorf("invalid vault data: %w", err)
		}
		iterations := 10000 // default iterations for v1 vaults
		if vault.KeyMetadata != nil {
			iterations = vault.KeyMetadata.Params.Iterations // use custom iterations from vault metadata for v2 vaults
		}
		if iterations <= 0 || len(iv) == 0 || len(data) < 16 || len(salt) == 0 {
			return nil, fmt.Errorf("invalid vault encryption parameters")
		}
		prepared = append(prepared, &preparedVault{Vault: vault, Salt: salt, Iv: iv, Data: data, Iterations: iterations})
	}
	return prepared, nil
}

// decrypt metamask vault
func decryptVault(password string, vault *preparedVault) ([]byte, bool) {
	key := pbkdf2.Key([]byte(password), vault.Salt, vault.Iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(vault.Iv))
	if err != nil {
		return nil, false
	}
	decryptedData, err := gcm.Open(nil, vault.Iv, vault.Data, nil)
	return decryptedData, err == nil
}

// print successfully decrypted metamask vault
func printDecryptedVault(password string, vault *MetamaskVault, decryptedData []byte) {
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
		return
	}

	for _, v := range vaultData {
		mnemonic, isString := v.Data.Mnemonic.(string)
		if isString {
			if len(mnemonic) > 0 {
				fmt.Printf("\nDecrypted Vault: '%.64s...'\nSeed Phrase:\t'%s'\nVault Password:\t'%s'\n", fmt.Sprintf("%v", *vault), mnemonic, password)
				return
			}
		} else if mnemonicSlice, isArray := v.Data.Mnemonic.([]interface{}); isArray {
			mnemonicStr := make([]byte, len(mnemonicSlice))
			for i, val := range mnemonicSlice {
				n, ok := val.(float64)
				if !ok {
					// skip unexpected mnemonic data
					mnemonicStr = nil
					break
				}
				mnemonicStr[i] = byte(n)
			}
			if len(mnemonicStr) > 0 {
				fmt.Printf("\nDecrypted Vault: '%.64s...'\nSeed Phrase:\t'%s'\nVault Password:\t'%s'\n", fmt.Sprintf("%v", *vault), string(mnemonicStr), password)
				return
			}
		}
	}
	fmt.Printf("\nDecryption successful\nDecrypted String: '%s'\nVault Password: '%s'\n", string(decryptedData), password)
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
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var vault MetamaskVault
		if err := json.Unmarshal([]byte(line), &vault); err != nil {
			// support JSON strings containing escaped vault JSON
			var encoded string
			if json.Unmarshal([]byte(line), &encoded) != nil || json.Unmarshal([]byte(encoded), &vault) != nil {
				// skip invalid json strings
				continue
			}
		}
		if vault.Data == "" || vault.Iv == "" || vault.Salt == "" {
			continue
		}
		// store vaults into map to deduplicate
		key := vault.Data + ":" + vault.Iv + ":" + vault.Salt
		if vault.KeyMetadata != nil {
			key += fmt.Sprintf(":%s:%d", vault.KeyMetadata.Algorithm, vault.KeyMetadata.Params.Iterations)
		}
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

// rules: compile commands once, use byte operations in workers
type ruleOp struct {
	Code  byte
	X     int
	Y     int
	Char  byte
	Char2 byte
}

type rule []ruleOp

// rules use base-36 position arguments
func rulePos(ch byte) (int, bool) {
	switch {
	case ch >= '0' && ch <= '9':
		return int(ch - '0'), true
	case ch >= 'A' && ch <= 'Z':
		return int(ch-'A') + 10, true
	default:
		return 0, false
	}
}

// parse a rule, rejecting unsupported commands rather than skipping passwords
func parseRule(line string) (rule, error) {
	var ops rule
	for i := 0; i < len(line); {
		if line[i] == ' ' || line[i] == '\t' {
			i++
			continue
		}
		op := ruleOp{Code: line[i]}
		i++
		switch op.Code {
		case ':', 'l', 'u', 'c', 'r', 'd', '[', ']', '{', '}', 'k', 'K', 'E':
		case '$', '^':
			if i >= len(line) {
				return nil, fmt.Errorf("missing character for %q", op.Code)
			}
			op.Char = line[i]
			i++
		case 'D', 'T', 'Z', '\'', '+', '-':
			if i >= len(line) {
				return nil, fmt.Errorf("missing position for %q", op.Code)
			}
			var ok bool
			op.X, ok = rulePos(line[i])
			if !ok {
				return nil, fmt.Errorf("invalid position %q", line[i])
			}
			i++
		case 's':
			if len(line)-i < 2 {
				return nil, fmt.Errorf("missing replacement characters")
			}
			op.Char, op.Char2 = line[i], line[i+1]
			i += 2
		case 'i', 'o':
			if len(line)-i < 2 {
				return nil, fmt.Errorf("missing position or character for %q", op.Code)
			}
			var ok bool
			op.X, ok = rulePos(line[i])
			if !ok {
				return nil, fmt.Errorf("invalid position %q", line[i])
			}
			op.Char = line[i+1]
			i += 2
		case '*', 'O':
			if len(line)-i < 2 {
				return nil, fmt.Errorf("missing positions for %q", op.Code)
			}
			var ok bool
			op.X, ok = rulePos(line[i])
			if !ok {
				return nil, fmt.Errorf("invalid position %q", line[i])
			}
			op.Y, ok = rulePos(line[i+1])
			if !ok {
				return nil, fmt.Errorf("invalid position %q", line[i+1])
			}
			i += 2
		default:
			return nil, fmt.Errorf("unsupported rule command %q", op.Code)
		}
		ops = append(ops, op)
	}
	return ops, nil
}

// read all rules once; the parsed rules are shared read-only by workers
func loadRules(filePath string) ([]rule, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []rule
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsed, err := parseRule(line)
		if err != nil {
			return nil, fmt.Errorf("rule line %d: %w", lineNumber, err)
		}
		rules = append(rules, parsed)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("rule file contains no rules")
	}
	return rules, nil
}

func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func upperByte(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - ('a' - 'A')
	}
	return b
}

func toggleByte(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - ('a' - 'A')
	}
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// apply a parsed rule to a byte buffer (worker-local scratch space)
func applyRule(word []byte, commands rule) []byte {
	for _, op := range commands {
		switch op.Code {
		case ':': // no operation
		case 'l':
			for i := range word {
				word[i] = lowerByte(word[i])
			}
		case 'u':
			for i := range word {
				word[i] = upperByte(word[i])
			}
		case 'c':
			for i := range word {
				word[i] = lowerByte(word[i])
			}
			if len(word) > 0 {
				word[0] = upperByte(word[0])
			}
		case 'E':
			upperNext := true
			for i := range word {
				word[i] = lowerByte(word[i])
				if upperNext {
					word[i] = upperByte(word[i])
				}
				upperNext = word[i] == ' '
			}
		case 'r':
			for i, j := 0, len(word)-1; i < j; i, j = i+1, j-1 {
				word[i], word[j] = word[j], word[i]
			}
		case 'd':
			word = append(word, word...)
		case '$':
			word = append(word, op.Char)
		case '^':
			word = append(word, 0)
			copy(word[1:], word[:len(word)-1])
			word[0] = op.Char
		case '[':
			if len(word) > 0 {
				word = word[1:]
			}
		case ']':
			if len(word) > 0 {
				word = word[:len(word)-1]
			}
		case '{':
			if len(word) > 1 {
				first := word[0]
				copy(word, word[1:])
				word[len(word)-1] = first
			}
		case '}':
			if len(word) > 1 {
				last := word[len(word)-1]
				copy(word[1:], word[:len(word)-1])
				word[0] = last
			}
		case 'D':
			if op.X < len(word) {
				word = append(word[:op.X], word[op.X+1:]...)
			}
		case '\'':
			if op.X < len(word) {
				word = word[:op.X]
			}
		case 'T':
			if op.X < len(word) {
				word[op.X] = toggleByte(word[op.X])
			}
		case 's':
			for i := range word {
				if word[i] == op.Char {
					word[i] = op.Char2
				}
			}
		case 'o':
			if op.X < len(word) {
				word[op.X] = op.Char
			}
		case 'i':
			if op.X <= len(word) {
				word = append(word, 0)
				copy(word[op.X+1:], word[op.X:len(word)-1])
				word[op.X] = op.Char
			}
		case 'k':
			if len(word) >= 2 {
				word[0], word[1] = word[1], word[0]
			}
		case 'K':
			if len(word) >= 2 {
				i := len(word) - 1
				word[i-1], word[i] = word[i], word[i-1]
			}
		case '*':
			if op.X < len(word) && op.Y < len(word) {
				word[op.X], word[op.Y] = word[op.Y], word[op.X]
			}
		case 'O':
			if op.X < len(word) {
				end := op.X + op.Y
				if end > len(word) {
					end = len(word)
				}
				word = append(word[:op.X], word[end:]...)
			}
		case 'Z':
			if len(word) > 0 {
				last := word[len(word)-1]
				for i := 0; i < op.X; i++ {
					word = append(word, last)
				}
			}
		case '+':
			if op.X < len(word) {
				word[op.X]++
			}
		case '-':
			if op.X < len(word) {
				word[op.X]--
			}
		}
	}
	return word
}

// print welcome screen
func printWelcomeScreen(vaultFileFlag, wordlistFileFlag *string, validVaultCount, numThreads int, ruleFile string, ruleCount int) {
	fmt.Fprintln(os.Stderr, " ------------------------------------ ")
	fmt.Fprintln(os.Stderr, "| Cyclone's Metamask Vault Decryptor |")
	fmt.Fprintln(os.Stderr, " ------------------------------------ ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Vault file:\t%s\n", *vaultFileFlag)
	fmt.Fprintf(os.Stderr, "Valid Vaults:\t%d\n", validVaultCount)
	fmt.Fprintf(os.Stderr, "CPU Threads:\t%d\n", numThreads)
	fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	if ruleCount > 0 {
		fmt.Fprintf(os.Stderr, "Rules:\t\t%s (%d)\n", ruleFile, ruleCount)
	}
	fmt.Fprintln(os.Stderr, "Working...")
}

// hash cracking worker
func startWorker(ch <-chan string, stopChan <-chan struct{}, vaults []*preparedVault, rules []rule, attempts *atomic.Uint64, crackedCount *atomic.Uint64, stop func()) {
	// each goroutine reuses its own small map (no locks or unbounded global state)
	var seen map[string]struct{}
	if len(rules) > 1 {
		seen = make(map[string]struct{}, len(rules))
	}
	buf := make([]byte, 0, 256)
	vaultCount := uint64(len(vaults))

	checkPassword := func(password string) bool {
		if crackedCount.Load() == vaultCount {
			return true
		}
		for _, vault := range vaults {
			// once a vault is decrypted, never schedule another password for it
			if vault.Decrypted.Load() {
				continue
			}
			select {
			case <-stopChan:
				return true
			default:
			}
			attempts.Add(1) // one PBKDF2 computation equals one hash attempt
			decryptedData, ok := decryptVault(password, vault)
			if ok && vault.Decrypted.CompareAndSwap(false, true) {
				// only one worker records and prints the result for each vault
				if crackedCount.Add(1) == vaultCount {
					stop() // all vaults decrypted
				}
				printDecryptedVault(password, &vault.Vault, decryptedData)
			}
		}
		return crackedCount.Load() == vaultCount
	}

	for {
		select {
		case <-stopChan:
			return
		case word, ok := <-ch:
			if !ok {
				return // EOF: drain queue, then finish normally
			}
			if len(rules) == 0 {
				if checkPassword(word) {
					return
				}
				continue
			}

			if seen != nil {
				clear(seen) // deduplicate only rule results for this base word
			}
			for _, commands := range rules {
				select {
				case <-stopChan:
					return
				default:
				}
				buf = append(buf[:0], word...)
				password := string(applyRule(buf, commands))
				if seen != nil {
					if _, exists := seen[password]; exists {
						continue
					}
					seen[password] = struct{}{}
				}
				if checkPassword(password) {
					return
				}
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
func handleGracefulShutdown(stopChan <-chan struct{}, stop func()) func() {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-interruptChan:
			fmt.Fprintln(os.Stderr, "\nCtrl+C pressed. Shutting down...")
			stop()
		case <-stopChan:
		}
	}()
	return func() { signal.Stop(interruptChan) }
}

// monitor status
func monitorPrintStats(attempts, crackedCount *atomic.Uint64, done <-chan struct{}, startTime time.Time, validVaultCount int, interval int) {
	var ticker *time.Ticker
	var tickerCh <-chan time.Time
	if interval > 0 {
		ticker = time.NewTicker(time.Duration(interval) * time.Second)
		tickerCh = ticker.C
		defer ticker.Stop()
	}
	for {
		select {
		case <-done:
			printStats(time.Since(startTime), crackedCount.Load(), validVaultCount, attempts.Load())
			return
		case <-tickerCh:
			printStats(time.Since(startTime), crackedCount.Load(), validVaultCount, attempts.Load())
		}
	}
}

// printStats
func printStats(elapsedTime time.Duration, crackedCount uint64, validVaultCount int, attempts uint64) {
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	linesPerSecond := float64(0)
	if elapsedTime.Seconds() > 0 {
		linesPerSecond = float64(attempts) / elapsedTime.Seconds()
	}
	fmt.Fprintf(os.Stderr, "\nDecrypted: %d/%d", crackedCount, validVaultCount)
	fmt.Fprintf(os.Stderr, "\t%.2f h/s", linesPerSecond)
	fmt.Fprintf(os.Stderr, "\t%02dh:%02dm:%02ds\n", hours, minutes, seconds)
}

// main func
func main() {
	wordlistFileFlag := flag.String("w", "", "Wordlist file")
	vaultFileFlag := flag.String("h", "", "Vault file")
	ruleFileFlag := flag.String("r", "", "Rules file (optional)")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
	threadFlag := flag.Int("t", runtime.NumCPU(), "CPU threads to use (optional)")
	statsIntervalFlag := flag.Int("s", 60, "Interval in seconds for printing stats. Defaults to 60.")
	flag.Parse()

	// run sanity checks for special flags
	if *versionFlag {
		versionFunc()
		return
	}
	if *cycloneFlag {
		line := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		str, _ := base64.StdEncoding.DecodeString(line)
		fmt.Println(string(str))
		return
	}
	if *helpFlag {
		helpFunc()
		return
	}
	if *wordlistFileFlag == "" || *vaultFileFlag == "" {
		fmt.Fprintln(os.Stderr, "Both -w (wordlist file) and -h (vault file) flags are required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	// read and compile rules before starting workers
	var rules []rule
	if *ruleFileFlag != "" {
		var err error
		rules, err = loadRules(*ruleFileFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading rules:", err)
			os.Exit(1)
		}
	}

	// read vaults
	vaults, err := ReadMetamaskJSON(*vaultFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading vault file:", err)
		os.Exit(1)
	}
	if len(vaults) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No valid MetaMask vaults found")
		os.Exit(1)
	}
	prepared, err := prepareVaults(vaults)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error preparing vault:", err)
		os.Exit(1)
	}

	// open wordlist before starting goroutines (so errors are reported correctly)
	wordlistFile, err := os.Open(*wordlistFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening wordlist file:", err)
		os.Exit(1)
	}
	defer wordlistFile.Close()

	startTime := time.Now()
	numThreads := setNumThreads(*threadFlag)
	printWelcomeScreen(vaultFileFlag, wordlistFileFlag, len(prepared), numThreads, *ruleFileFlag, len(rules))

	// channels / variables
	wordChan := make(chan string, numThreads*4) // shared queue balances slow and fast rules
	stopChan := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(stopChan) }) }
	var attempts atomic.Uint64
	var crackedCount atomic.Uint64
	var wg sync.WaitGroup
	stopSignals := handleGracefulShutdown(stopChan, stop)
	defer stopSignals()

	// start worker goroutines
	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startWorker(wordChan, stopChan, prepared, rules, &attempts, &crackedCount, stop)
		}()
	}

	// monitor status of workers
	done := make(chan struct{})
	var statusWg sync.WaitGroup
	statusWg.Add(1)
	go func() {
		defer statusWg.Done()
		monitorPrintStats(&attempts, &crackedCount, done, startTime, len(prepared), *statsIntervalFlag)
	}()

	// read wordlist and distribute to workers
	scanner := bufio.NewScanner(wordlistFile)
readLoop:
	for scanner.Scan() {
		word := scanner.Text() // ScanLines already handles LF and CRLF
		select {
		case <-stopChan:
			break readLoop
		case wordChan <- word:
		}
	}

	// check scanner errors after scanning
	readErr := scanner.Err()
	close(wordChan) // close once at EOF; workers drain all queued words
	wg.Wait()       // wait for all worker goroutines to finish
	close(done)     // print final stats only after workers are finished
	statusWg.Wait()
	stop()

	if readErr != nil {
		fmt.Fprintln(os.Stderr, "Error reading wordlist:", readErr)
		os.Exit(1)
	}
}

// end code
