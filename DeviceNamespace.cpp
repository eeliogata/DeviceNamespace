#include <windows.h>
#include <sddl.h>
#include <winternl.h>

#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr ULONG device_information_class = 4;
constexpr ULONG secure_open = 0x100;
constexpr ULONG synchronous_open = 0x20;
constexpr NTSTATUS pending = 0x103;

struct BasicInfo {
    ULONG attributes;
    ACCESS_MASK granted_access;
    ULONG handle_count;
    ULONG pointer_count;
    ULONG reserved[10];
};

struct DeviceInfo {
    ULONG type;
    ULONG characteristics;
};

using CreateFileFn = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
using QueryObjectFn = NTSTATUS(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using QueryVolumeFn = NTSTATUS(NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
using GetVersionFn = NTSTATUS(NTAPI *)(OSVERSIONINFOW *);

struct Native {
    CreateFileFn create_file;
    QueryObjectFn query_object;
    QueryVolumeFn query_volume;
    GetVersionFn get_version;
};

template <typename T>
T resolve(HMODULE module, const char *name) {
    FARPROC address = GetProcAddress(module, name);
    static_assert(sizeof(address) == sizeof(T));
    T function{};
    std::memcpy(&function, &address, sizeof(function));
    return function;
}

std::wstring hex32(ULONG value) {
    std::wostringstream out;
    out << L"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0') << value;
    return out.str();
}

bool success(NTSTATUS status) {
    return status >= 0 && status != pending;
}

std::wstring sid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return L"unavailable";

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    std::wstring result = L"unavailable";
    if (size && GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        auto user = reinterpret_cast<TOKEN_USER *>(buffer.data());
        LPWSTR value = nullptr;
        if (ConvertSidToStringSidW(user->User.Sid, &value)) {
            result = value;
            LocalFree(value);
        }
    }
    CloseHandle(token);
    return result;
}

std::wstring elevation() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return L"unknown";
    TOKEN_ELEVATION value{};
    DWORD size = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &value, sizeof(value), &size);
    CloseHandle(token);
    return ok ? (value.TokenIsElevated ? L"yes" : L"no") : L"unknown";
}

NTSTATUS probe(const Native &nt, const wchar_t *label, std::wstring path, ACCESS_MASK access) {
    UNICODE_STRING name{};
    name.Buffer = path.data();
    name.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
    name.MaximumLength = name.Length;

    OBJECT_ATTRIBUTES object{};
    object.Length = sizeof(object);
    object.ObjectName = &name;
    object.Attributes = OBJ_CASE_INSENSITIVE;

    IO_STATUS_BLOCK io{};
    HANDLE handle = nullptr;
    NTSTATUS status = nt.create_file(&handle, access, &object, &io, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, synchronous_open, nullptr, 0);

    std::wcout << label << L" " << path << L"\n  status " << hex32(static_cast<ULONG>(status));
    if (!success(status)) {
        std::wcout << L'\n';
        if (handle) CloseHandle(handle);
        return status;
    }
    std::wcout << L'\n';

    BasicInfo basic{};
    NTSTATUS query = nt.query_object(handle, 0, &basic, sizeof(basic), nullptr);
    if (success(query)) {
        std::wcout << L"  granted " << hex32(basic.granted_access) << L'\n';
    } else {
        std::wcout << L"  granted unavailable (" << hex32(static_cast<ULONG>(query)) << L")\n";
    }

    DeviceInfo device{};
    IO_STATUS_BLOCK device_io{};
    query = nt.query_volume(handle, &device_io, &device, sizeof(device), device_information_class);
    if (success(query)) {
        std::wcout << L"  device_type " << hex32(device.type)
                   << L" characteristics " << hex32(device.characteristics)
                   << L" secure_open " << ((device.characteristics & secure_open) ? L"yes" : L"no") << L'\n';
    } else {
        std::wcout << L"  device_type unavailable (" << hex32(static_cast<ULONG>(query)) << L")\n";
    }
    CloseHandle(handle);
    return status;
}

bool parse_access(const wchar_t *text, ACCESS_MASK &value) {
    if (!*text || *text == L'-' || *text == L'+') return false;
    wchar_t *end = nullptr;
    unsigned long long parsed = std::wcstoull(text, &end, 0);
    if (!end || *end || parsed > std::numeric_limits<ULONG>::max()) return false;
    value = static_cast<ACCESS_MASK>(parsed);
    return true;
}

void usage() {
    std::wcerr << L"usage: DeviceNamespace.exe <\\Device\\Name> [--access mask] [--child name]\n";
}

}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    std::wstring root = argv[1];
    std::wstring child = L"dn_probe";
    ACCESS_MASK requested = FILE_READ_DATA;
    for (int i = 2; i < argc; i++) {
        if (std::wcscmp(argv[i], L"--access") == 0 && i + 1 < argc) {
            if (!parse_access(argv[++i], requested)) {
                usage();
                return 1;
            }
        } else if (std::wcscmp(argv[i], L"--child") == 0 && i + 1 < argc) {
            child = argv[++i];
        } else {
            usage();
            return 1;
        }
    }
    if (root.rfind(L"\\Device\\", 0) != 0 || root.size() <= 8 || root.back() == L'\\' ||
        child.empty() || child == L"." || child == L".." ||
        child.find_first_of(L"\\/:") != std::wstring::npos ||
        root.size() + child.size() + 1 > (std::numeric_limits<USHORT>::max() / sizeof(wchar_t))) {
        usage();
        return 1;
    }

    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    if (!module) return 1;
    Native nt{
        resolve<CreateFileFn>(module, "NtCreateFile"),
        resolve<QueryObjectFn>(module, "NtQueryObject"),
        resolve<QueryVolumeFn>(module, "NtQueryVolumeInformationFile"),
        resolve<GetVersionFn>(module, "RtlGetVersion")
    };
    if (!nt.create_file || !nt.query_object || !nt.query_volume || !nt.get_version) {
        std::wcerr << L"ntdll exports unavailable\n";
        return 1;
    }

    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (!success(nt.get_version(&version))) {
        std::wcerr << L"RtlGetVersion failed\n";
        return 1;
    }

    ACCESS_MASK access = requested | SYNCHRONIZE;
    std::wcout << L"windows " << version.dwMajorVersion << L'.' << version.dwMinorVersion
               << L'.' << version.dwBuildNumber << L" sid " << sid()
               << L" elevated " << elevation() << L'\n'
               << L"requested " << hex32(requested) << L" effective " << hex32(access) << L'\n';
    NTSTATUS root_status = probe(nt, L"root", root, access);
    NTSTATUS child_status = probe(nt, L"child", root + L'\\' + child, access);
    if (root_status == static_cast<NTSTATUS>(0xC0000022) && success(child_status)) {
        std::wcout << L"candidate: root denied, child opened\n";
    }
    return 0;
}
