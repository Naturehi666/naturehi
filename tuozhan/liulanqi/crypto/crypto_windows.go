//go:build windows

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var (
	crypt32                     = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData      = crypt32.NewProc("CryptUnprotectData")
	advapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = advapi32.NewProc("RevertToSelf")
	ntdll                       = syscall.NewLazyDLL("ntdll.dll")
	procRtlAdjustPrivilege      = ntdll.NewProc("RtlAdjustPrivilege")
)

func DecryptPass(key, encryptPass []byte) ([]byte, error) {
	if len(encryptPass) < 15 {
		return nil, errPasswordIsEmpty
	}

	return aesGCMDecrypt(encryptPass[15:], key, encryptPass[3:15])
}

func DecryptPassForYandex(key, encryptPass []byte) ([]byte, error) {
	if len(encryptPass) < 3 {
		return nil, errPasswordIsEmpty
	}
	// remove Prefix 'v10'
	// gcmBlockSize         = 16
	// gcmTagSize           = 16
	// gcmMinimumTagSize    = 12 // NIST SP 800-38D recommends tags with 12 or more bytes.
	// gcmStandardNonceSize = 12
	return aesGCMDecrypt(encryptPass[12:], key, encryptPass[0:12])
}

// chromium > 80 https://source.chromium.org/chromium/chromium/src/+/master:components/os_crypt/os_crypt_win.cc
func aesGCMDecrypt(crypted, key, nounce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil
	}
	blockMode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil
	}
	origData, err := blockMode.Open(nil, nounce, crypted, nil)
	if err != nil {
		return nil, nil
	}
	return origData, nil
}

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *dataBlob) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

// DPAPI (Data Protection Application Programming Interface)
// is a simple cryptographic application programming interface
// available as a built-in component in Windows 2000 and
// later versions of Microsoft Windows operating systems
// chrome < 80 https://chromium.googlesource.com/chromium/src/+/76f496a7235c3432983421402951d73905c8be96/components/os_crypt/os_crypt_win.cc#82
func DPAPI(data []byte) ([]byte, error) {
	dllCrypt := syscall.NewLazyDLL("Crypt32.dll")
	dllKernel := syscall.NewLazyDLL("Kernel32.dll")
	procDecryptData := dllCrypt.NewProc("CryptUnprotectData")
	procLocalFree := dllKernel.NewProc("LocalFree")
	var outBlob dataBlob
	r, _, _ := procDecryptData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outBlob)))
	if r == 0 {
		return nil, nil
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.ToByteArray(), nil
}

func enablePrivilege() error {
	var privilege uint32 = 20
	var previousValue uint32 = 0

	ret, _, _ := procRtlAdjustPrivilege.Call(
		uintptr(privilege),
		uintptr(1),
		uintptr(0),
		uintptr(unsafe.Pointer(&previousValue)),
	)

	if ret != 0 {
		return fmt.Errorf("RtlAdjustPrivilege failed with status: %x", ret)
	}

	return nil
}

func findLsassProcess() (*windows.Handle, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(h)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err = windows.Process32First(h, &pe); err != nil {
		return nil, fmt.Errorf("Process32First failed: %v", err)
	}

	for {
		name := windows.UTF16ToString(pe.ExeFile[:])
		if name == "lsass.exe" {
			handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pe.ProcessID)
			if err != nil {
				return nil, fmt.Errorf("OpenProcess failed: %v", err)
			}
			return &handle, nil
		}

		err = windows.Process32Next(h, &pe)
		if err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return nil, fmt.Errorf("Process32Next failed: %v", err)
		}
	}

	return nil, fmt.Errorf("lsass.exe not found")
}

func getSystemToken() (windows.Token, error) {
	if err := enablePrivilege(); err != nil {
		return 0, fmt.Errorf("failed to enable privileges: %v", err)
	}

	processHandle, err := findLsassProcess()
	if err != nil {
		return 0, fmt.Errorf("failed to find LSASS process: %v", err)
	}
	defer windows.CloseHandle(*processHandle)

	var token windows.Token
	err = windows.OpenProcessToken(*processHandle, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &token)
	if err != nil {
		return 0, fmt.Errorf("OpenProcessToken failed: %v", err)
	}

	var duplicatedToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &duplicatedToken)
	if err != nil {
		token.Close()
		return 0, fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	token.Close()

	return duplicatedToken, nil
}

func impersonateSystem() (windows.Token, error) {
	token, err := getSystemToken()
	if err != nil {
		return 0, err
	}

	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(token))
	if ret == 0 {
		token.Close()
		return 0, fmt.Errorf("ImpersonateLoggedOnUser failed: %v", err)
	}

	return token, nil
}

func Dpapi_decrypt(data []byte, asSystem bool) ([]byte, error) {
	if asSystem {
		token, err := impersonateSystem()
		if err != nil {
			return nil, fmt.Errorf("failed to impersonate SYSTEM: %v", err)
		}
		defer token.Close()
		defer procRevertToSelf.Call()
	}

	var dataIn, dataOut dataBlob
	var entropy dataBlob

	dataIn.cbData = uint32(len(data))
	dataIn.pbData = &data[0]

	flags := uint32(1) // CRYPTPROTECT_UI_FORBIDDEN

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&dataIn)),
		0,
		uintptr(unsafe.Pointer(&entropy)),
		0,
		0,
		uintptr(flags),
		uintptr(unsafe.Pointer(&dataOut)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}

	defer syscall.LocalFree(syscall.Handle(unsafe.Pointer(dataOut.pbData)))

	decrypted := make([]byte, dataOut.cbData)
	copy(decrypted, unsafe.Slice(dataOut.pbData, dataOut.cbData))

	return decrypted, nil
}
