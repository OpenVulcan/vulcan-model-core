//go:build windows

package secret

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiProtector protects secret bytes with the current Windows user DPAPI scope.
// dpapiProtector 使用当前 Windows 用户的 DPAPI 范围保护 Secret 字节。
type dpapiProtector struct{}

// newPlatformProtector returns the current-user Windows DPAPI implementation.
// newPlatformProtector 返回当前用户的 Windows DPAPI 实现。
func newPlatformProtector() (Protector, error) {
	return dpapiProtector{}, nil
}

// Protect encrypts one secret using Windows DPAPI without any visible prompt.
// Protect 使用 Windows DPAPI 且不显示提示来加密一个 Secret。
func (dpapiProtector) Protect(value []byte) ([]byte, error) {
	input := blobFromBytes(value)
	// output is allocated by Windows and must be released with LocalFree.
	// output 由 Windows 分配，必须通过 LocalFree 释放。
	var output windows.DataBlob
	if errProtect := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); errProtect != nil {
		return nil, fmt.Errorf("DPAPI protect data: %w", errProtect)
	}
	defer freeDataBlob(output)
	return copyDataBlob(output), nil
}

// Unprotect decrypts one current-user Windows DPAPI payload without any visible prompt.
// Unprotect 使用当前用户 Windows DPAPI 且不显示提示来解密一个载荷。
func (dpapiProtector) Unprotect(value []byte) ([]byte, error) {
	input := blobFromBytes(value)
	// output is allocated by Windows and must be released with LocalFree.
	// output 由 Windows 分配，必须通过 LocalFree 释放。
	var output windows.DataBlob
	if errUnprotect := windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); errUnprotect != nil {
		return nil, fmt.Errorf("DPAPI unprotect data: %w", errUnprotect)
	}
	defer freeDataBlob(output)
	return copyDataBlob(output), nil
}

// blobFromBytes creates one Windows DataBlob over bytes that remain live for the immediate syscall.
// blobFromBytes 为在即时系统调用期间保持存活的字节创建一个 Windows DataBlob。
func blobFromBytes(value []byte) windows.DataBlob {
	if len(value) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(value)), Data: &value[0]}
}

// copyDataBlob returns an isolated Go-owned copy of a Windows-allocated DataBlob.
// copyDataBlob 返回由 Go 拥有的 Windows 分配 DataBlob 隔离副本。
func copyDataBlob(blob windows.DataBlob) []byte {
	if blob.Size == 0 || blob.Data == nil {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(blob.Data, int(blob.Size))...)
}

// freeDataBlob releases the Windows local-memory allocation returned by DPAPI.
// freeDataBlob 释放 DPAPI 返回的 Windows 本地内存分配。
func freeDataBlob(blob windows.DataBlob) {
	if blob.Data == nil {
		return
	}
	_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(blob.Data))))
}
