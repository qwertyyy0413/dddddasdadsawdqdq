package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

func generateKey() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

func generateXorPair(key []byte) ([]byte, []byte) {
	partB := generateKey()
	partA := make([]byte, 16)
	for i := 0; i < 16; i++ {
		partA[i] = key[i] ^ partB[i]
	}
	return partA, partB
}

func formatCArray(name string, data []byte) string {
	hexVals := []string{}
	for _, b := range data {
		hexVals = append(hexVals, fmt.Sprintf("0x%02X", b))
	}
	return fmt.Sprintf("static const uint8_t %s[16] = {\n    %s\n};", name, strings.Join(hexVals, ", "))
}

func main() {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("         ASCON KEY GENERATOR")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	masterKey := generateKey()
	partA, partB := generateXorPair(masterKey)

	reconstructed := make([]byte, 16)
	for i := 0; i < 16; i++ {
		reconstructed[i] = partA[i] ^ partB[i]
	}

	for i := 0; i < 16; i++ {
		if reconstructed[i] != masterKey[i] {
			panic("XOR pair verification failed!")
		}
	}

	fmt.Println("MASTER KEY (for reference only, do NOT hardcode this):")
	fmt.Printf("  %s\n\n", hex.EncodeToString(masterKey))

	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("C FORMAT (bot/keyguard.c)")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println()
	fmt.Println(formatCArray("MASTER_PART_A", partA))
	fmt.Println()
	fmt.Println(formatCArray("MASTER_PART_B", partB))
	fmt.Println()

	fmt.Println(strings.Repeat("-", 60))
	fmt.Println(".ENV FORMAT (copy to .env)")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println()
	fmt.Printf("OVERBYTE_CRYPTO_KEY=%s\n\n", hex.EncodeToString(masterKey))

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("VERIFICATION: PART_A ^ PART_B = MASTER_KEY")
	fmt.Printf("  %s\n", hex.EncodeToString(partA))
	fmt.Printf("^ %s\n", hex.EncodeToString(partB))
	fmt.Printf("= %s\n", hex.EncodeToString(reconstructed))
	fmt.Println(strings.Repeat("=", 60))
}
