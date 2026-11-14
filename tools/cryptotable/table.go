package cryptotable

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"strings"
)

func rotr64(x uint64, n int) uint64 {
	return bits.RotateLeft64(x, -n)
}

func asconRound(s []uint64, c uint64) {
	s[2] ^= c
	s[0] ^= s[4]
	s[4] ^= s[3]
	s[2] ^= s[1]

	t := make([]uint64, 5)
	for i := 0; i < 5; i++ {
		t[i] = s[i] & (^s[(i+1)%5])
	}
	for i := 0; i < 5; i++ {
		s[i] ^= t[(i+1)%5]
	}

	s[1] ^= s[0]
	s[0] ^= s[4]
	s[3] ^= s[2]
	s[2] = ^s[2]

	s[0] ^= rotr64(s[0], 19) ^ rotr64(s[0], 28)
	s[1] ^= rotr64(s[1], 61) ^ rotr64(s[1], 39)
	s[2] ^= rotr64(s[2], 1) ^ rotr64(s[2], 6)
	s[3] ^= rotr64(s[3], 10) ^ rotr64(s[3], 17)
	s[4] ^= rotr64(s[4], 7) ^ rotr64(s[4], 41)
}

var asconConstants = []uint64{
	0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
}

func asconPermutation(s []uint64, rounds int) {
	start := 12 - rounds
	for i := start; i < 12; i++ {
		asconRound(s, asconConstants[i])
	}
}

func ascon128Encrypt(key, nonce, plaintext, ad []byte) []byte {
	s := []uint64{
		0x80400c0600000000,
		binary.BigEndian.Uint64(key[:8]),
		binary.BigEndian.Uint64(key[8:]),
		binary.BigEndian.Uint64(nonce[:8]),
		binary.BigEndian.Uint64(nonce[8:]),
	}
	asconPermutation(s, 12)
	s[3] ^= binary.BigEndian.Uint64(key[:8])
	s[4] ^= binary.BigEndian.Uint64(key[8:])

	if len(ad) == 0 {
		s[4] ^= 1
	} else {
		i := 0
		for i+8 <= len(ad) {
			s[0] ^= binary.BigEndian.Uint64(ad[i : i+8])
			asconPermutation(s, 6)
			i += 8
		}
		padded := make([]byte, 8)
		rem := len(ad) - i
		copy(padded[:rem], ad[i:])
		padded[rem] = 0x80
		s[0] ^= binary.BigEndian.Uint64(padded)
		asconPermutation(s, 6)
		s[4] ^= 1
	}

	var ct []byte
	i := 0
	for i+8 <= len(plaintext) {
		s[0] ^= binary.BigEndian.Uint64(plaintext[i : i+8])
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, s[0])
		ct = append(ct, buf...)
		asconPermutation(s, 6)
		i += 8
	}
	rem := len(plaintext) - i
	if rem > 0 {
		padded := make([]byte, 8)
		copy(padded[:rem], plaintext[i:])
		padded[rem] = 0x80
		s[0] ^= binary.BigEndian.Uint64(padded)
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, s[0])
		ct = append(ct, buf[:rem]...)
	}

	s[1] ^= binary.BigEndian.Uint64(key[:8])
	s[2] ^= binary.BigEndian.Uint64(key[8:])
	asconPermutation(s, 12)
	s[3] ^= binary.BigEndian.Uint64(key[:8])
	s[4] ^= binary.BigEndian.Uint64(key[8:])

	tag := make([]byte, 16)
	binary.BigEndian.PutUint64(tag[:8], s[3])
	binary.BigEndian.PutUint64(tag[8:], s[4])

	return append(ct, tag...)
}

func hmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}
	return hmacSha256(salt, ikm)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	n := (length + 31) / 32
	var okm []byte
	var t []byte
	for i := 1; i <= n; i++ {
		t = hmacSha256(prk, append(append(t, info...), byte(i)))
		okm = append(okm, t...)
	}
	return okm[:length]
}

func hkdfSha256(salt, ikm, info []byte, length int) []byte {
	prk := hkdfExtract(salt, ikm)
	return hkdfExpand(prk, info, length)
}

func reconstructTableKey(k1, k2, k3, k4 []byte) []byte {
	ikm := make([]byte, 32)
	salt := make([]byte, 32)
	for i := 0; i < 32; i++ {
		ikm[i] = k1[i] ^ k2[i]
		salt[i] = k3[i] ^ k4[i]
	}
	return hkdfSha256(salt, ikm, []byte("TABLE-MASTER-V2"), 16)
}

func deriveEntryKey(master []byte, entryID uint32) []byte {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, entryID)
	return hkdfSha256(salt, master, []byte("TABLE-ENTRY-V2"), 16)
}

func toHexArray(name string, data []byte) string {
	var hexVals []string
	for _, b := range data {
		hexVals = append(hexVals, fmt.Sprintf("0x%02x", b))
	}
	return fmt.Sprintf("static const uint8_t %s[] = { %s };", name, strings.Join(hexVals, ", "))
}

// WriteTableC writes bot/table.c content for the given plaintext secrets (one table row each).
func WriteTableC(w io.Writer, secrets []string) error {
	randBytes := func(n int) []byte {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		return b
	}

	kP1 := randBytes(32)
	kP2 := randBytes(32)
	kP3 := randBytes(32)
	kP4 := randBytes(32)

	master := reconstructTableKey(kP1, kP2, kP3, kP4)

	_, err := fmt.Fprintln(w, "#include <stdio.h>")
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "#include <stdint.h>")
	fmt.Fprintln(w, "#include <string.h>")
	fmt.Fprintln(w, "#include <stdlib.h>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "#include \"headers/table.h\"")
	fmt.Fprintln(w, "#include \"headers/ascon.h\"")
	fmt.Fprintln(w, "#include \"headers/hkdf.h\"")
	fmt.Fprintln(w)

	fmt.Fprintln(w, toHexArray("k_p1", kP1))
	fmt.Fprintln(w, toHexArray("k_p2", kP2))
	fmt.Fprintln(w, toHexArray("k_p3", kP3))
	fmt.Fprintln(w, toHexArray("k_p4", kP4))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "typedef struct { const unsigned char* d; int l; const unsigned char* n; } entry_t;")
	fmt.Fprintln(w)

	for i, s := range secrets {
		entryKey := deriveEntryKey(master, uint32(i))
		nonce := randBytes(16)
		ctWithTag := ascon128Encrypt(entryKey, nonce, []byte(s), nil)

		fmt.Fprintln(w, toHexArray(fmt.Sprintf("n_%d", i), nonce))
		fmt.Fprintln(w, toHexArray(fmt.Sprintf("d_%d", i), ctWithTag))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "static const entry_t TABLE[] = {")
	for i, s := range secrets {
		fmt.Fprintf(w, "    { d_%d, %d, n_%d },\n", i, len(s), i)
	}
	fmt.Fprintln(w, "};")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "#define TABLE_SIZE %d\n", len(secrets))
	fmt.Fprintln(w)

	_, err = fmt.Fprint(w, `void secure_memzero(void *v, size_t n) {
    volatile unsigned char *p = v;
    while (n--) {
        *p++ = 0;
    }
}

static void reconstruct_table_key(uint8_t key_out[ASCON_KEY_LEN]) {
    uint8_t ikm[32], salt[32];
    int i;
    for (i = 0; i < 32; i++) {
        ikm[i] = k_p1[i] ^ k_p2[i];
        salt[i] = k_p3[i] ^ k_p4[i];
    }
    hkdf_sha256(salt, 32, ikm, 32, (const uint8_t *)"TABLE-MASTER-V2", 15, key_out, ASCON_KEY_LEN);
    secure_memzero(ikm, sizeof(ikm));
    secure_memzero(salt, sizeof(salt));
}

static void derive_entry_key(const uint8_t *master, int id, uint8_t entry_key[ASCON_KEY_LEN]) {
    uint8_t salt[4];
    salt[0] = (id >> 24) & 0xFF;
    salt[1] = (id >> 16) & 0xFF;
    salt[2] = (id >> 8) & 0xFF;
    salt[3] = id & 0xFF;
    hkdf_sha256(salt, sizeof(salt), master, ASCON_KEY_LEN, (const uint8_t *)"TABLE-ENTRY-V2", 14, entry_key, ASCON_KEY_LEN);
}

char *decrypt(int id) {
    if (id < 0 || id >= TABLE_SIZE) {
        return NULL;
    }

    int plen = TABLE[id].l;
    if (plen <= 0) {
        return NULL;
    }

    unsigned char *buf = malloc(sizeof(size_t) + plen + 1);
    if (!buf) {
        return NULL;
    }

    *((size_t *)buf) = (size_t)plen;
    char *plain = (char *)(buf + sizeof(size_t));

    uint8_t master[ASCON_KEY_LEN];
    reconstruct_table_key(master);

    uint8_t entry_key[ASCON_KEY_LEN];
    derive_entry_key(master, id, entry_key);
    secure_memzero(master, sizeof(master));

    size_t ct_len = (size_t)plen + ASCON_TAG_LEN;
    size_t decrypted_len;
    int ret = ascon128_aead_decrypt((uint8_t *)plain, &decrypted_len, TABLE[id].d, ct_len, NULL, 0, TABLE[id].n, entry_key);

    secure_memzero(entry_key, sizeof(entry_key));

    if (ret != 0) {
        secure_memzero(buf, sizeof(size_t) + plen + 1);
        free(buf);
        return NULL;
    }

    plain[plen] = '\0';
    return plain;
}

void free_secret(char *s) {
    if (!s) return;

    unsigned char *buf = (unsigned char *)s - sizeof(size_t);
    size_t len = *((size_t *)buf);

    secure_memzero(s, len);
    secure_memzero(buf, sizeof(size_t));
    free(buf);
}`)
	return err
}
