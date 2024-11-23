package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"searchall3.5/tuozhan/liulanqi/crypto"
)

type LocalState struct {
	OSCrypt struct {
		AppBoundEncryptedKey string `json:"app_bound_encrypted_key"`
	} `json:"os_crypt"`
}

func DecryptChromeKey() ([]byte, error) {

	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return nil, fmt.Errorf("USERPROFILE environment variable not set")
	}

	localStatePath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
	//localStatePath := filepath.Join(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Local State")

	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State: %v", err)
	}

	var localState LocalState
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, fmt.Errorf("failed to parse Local State: %v", err)
	}

	app_bound_encrypted_key := localState.OSCrypt.AppBoundEncryptedKey
	if app_bound_encrypted_key == "" {
		return nil, fmt.Errorf("no encrypted key found in Local State")
	}

	// decode from b64
	decoded, err := base64.StdEncoding.DecodeString(app_bound_encrypted_key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %v", err)
	}

	if string(decoded[:4]) != "APPB" {
		return nil, fmt.Errorf("invalid key prefix")
	}

	// decrypt with system elevation DPAPI
	decrypted1, err := crypto.Dpapi_decrypt(decoded[4:], true)
	if err != nil {
		return nil, fmt.Errorf("first DPAPI decrypt failed: %v", err)
	}

	// decrypt with user level DPAPI
	decrypted2, err := crypto.Dpapi_decrypt(decrypted1, false)
	if err != nil {
		return nil, fmt.Errorf("second DPAPI decrypt failed: %v", err)
	}

	// get last 61 bytes
	if len(decrypted2) < 61 {
		return nil, fmt.Errorf("decrypted key too short, got %d bytes", len(decrypted2))
	}
	decrypted_key := decrypted2[len(decrypted2)-61:]

	if decrypted_key[0] != 1 {
		return nil, fmt.Errorf("invalid key format")
	}

	// decrypt key with AES256GCM
	aes_key, err := base64.StdEncoding.DecodeString("sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=")
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key: %v", err)
	}

	// key parts
	iv := decrypted_key[1 : 1+12]
	ciphertext := decrypted_key[1+12 : 1+12+32]
	tag := decrypted_key[1+12+32:]

	// create AES-GCM cipher
	block, err := aes.NewCipher(aes_key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// decrypt final key
	key, err := aesGCM.Open(nil, iv, append(ciphertext, tag...), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %v", err)
	}

	return key, nil
}

func DecryptCookieValue(encryptedValue []byte, key []byte) (string, error) {
	if len(encryptedValue) < 31 { // 3 (flag) + 12 (IV) + min_data + 16 (tag)
		return "", fmt.Errorf("encrypted value too short")
	}

	// extract IV, ciphertext, and tag, skipping the first 3 bytes
	cookieIV := encryptedValue[3:15]
	encryptedCookie := encryptedValue[15 : len(encryptedValue)-16]
	cookieTag := encryptedValue[len(encryptedValue)-16:]

	// combine encrypted data and tag for GCM decryption
	encryptedDataWithTag := append(encryptedCookie, cookieTag...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, cookieIV, encryptedDataWithTag, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	// chrome cookies have a 32-byte prefix in the plaintext that can be skipped
	if len(plaintext) <= 32 {
		return "", fmt.Errorf("decrypted value too short")
	}
	return string(plaintext[32:]), nil
}
