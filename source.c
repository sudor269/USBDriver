#include <fltKernel.h>
#include <ntddstor.h>
#include <ntstrsafe.h>

#define TAG 'BSBU'  

PFLT_FILTER gFilter = NULL;

typedef struct _CTX {
    BOOLEAN IsUsb;
    BOOLEAN Allowed;
    UINT64  SerialHash;
} CTX, * PCTX;

typedef struct _WHITELIST {
    UINT64* Items;
    ULONG   Count;
    EX_PUSH_LOCK Lock;
} WHITELIST;

static WHITELIST gWl = { 0 };

static VOID TrimSpaces(_Inout_ PWSTR s)
{
    if (!s) return;

    size_t len = wcslen(s);

    while (len > 0) {
        WCHAR c = s[len - 1];
        if (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') {
            s[len - 1] = L'\0';
            len--;
        }
        else break;
    }

    size_t start = 0;
    while (s[start] == L' ' || s[start] == L'\t' || s[start] == L'\r' || s[start] == L'\n') {
        start++;
    }

    if (start > 0) {
        size_t newLen = wcslen(s + start);
        memmove(s, s + start, (newLen + 1) * sizeof(WCHAR));
    }
}

static VOID NormalizeSerial(_Inout_ PWSTR s)
{
    if (!s) return;

    TrimSpaces(s);

    for (PWSTR p = s; *p; ++p) {
        if (*p == L'&') { *p = L'\0'; break; }
    }

    TrimSpaces(s);

    for (PWSTR p = s; *p; ++p) {
        if (*p >= L'a' && *p <= L'z') {
            *p = (WCHAR)(*p - (L'a' - L'A'));
        }
    }
}


static UINT64 HashSerial(_In_ PCWSTR s)
{
    const UINT64 FNV_OFFSET = 1469598103934665603ULL;
    const UINT64 FNV_PRIME = 1099511628211ULL;

    UINT64 h = FNV_OFFSET;
    if (!s) return h;

    for (const WCHAR* p = s; *p; ++p) {
        USHORT w = (USHORT)(*p);

        h ^= (UINT64)(w & 0xFF);
        h *= FNV_PRIME;

        h ^= (UINT64)((w >> 8) & 0xFF);
        h *= FNV_PRIME;
    }
    return h;
}

static BOOLEAN HexDigit(_In_ WCHAR c, _Out_ UCHAR* v)
{
    if (v) *v = 0; 

    if (!v) return FALSE;

    if (c >= L'0' && c <= L'9') { *v = (UCHAR)(c - L'0'); return TRUE; }
    if (c >= L'a' && c <= L'f') { *v = (UCHAR)(10 + (c - L'a')); return TRUE; }
    if (c >= L'A' && c <= L'F') { *v = (UCHAR)(10 + (c - L'A')); return TRUE; }

    return FALSE;
}

static BOOLEAN HexToU64(_In_ PCWSTR s, _Out_ UINT64* out)
{
    if (out) *out = 0; 
    if (!s || !out) return FALSE;

    WCHAR tmp[64];
    NTSTATUS st = RtlStringCchCopyW(tmp, ARRAYSIZE(tmp), s);
    if (!NT_SUCCESS(st)) return FALSE;

    TrimSpaces(tmp);

    size_t n = wcslen(tmp);
    if (n == 0 || n > 16) return FALSE;

    UINT64 val = 0;
    for (size_t i = 0; i < n; i++) {
        UCHAR d = 0;
        if (!HexDigit(tmp[i], &d)) return FALSE;
        val = (val << 4) | (UINT64)d;
    }

    *out = val;
    return TRUE;
}

static VOID WhitelistFree()
{
    ExAcquirePushLockExclusive(&gWl.Lock);
    if (gWl.Items) {
        ExFreePoolWithTag(gWl.Items, TAG);
        gWl.Items = NULL;
        gWl.Count = 0;
    }
    ExReleasePushLockExclusive(&gWl.Lock);
}

static NTSTATUS ReadWhitelistFromRegistry(_In_ PUNICODE_STRING RegistryPath)
{
    WCHAR keyBuf[512];
    UNICODE_STRING paramsPath;

    NTSTATUS st = RtlStringCchPrintfW(
        keyBuf, ARRAYSIZE(keyBuf),
        L"%wZ\\Parameters",
        RegistryPath
    );
    if (!NT_SUCCESS(st)) return st;

    RtlInitUnicodeString(&paramsPath, keyBuf);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &paramsPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hKey = NULL;
    st = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(st)) {
        WhitelistFree();
        return STATUS_SUCCESS;
    }

    UNICODE_STRING valName;
    RtlInitUnicodeString(&valName, L"WhitelistHashes");

    ULONG need = 0;
    st = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &need);
    if (st != STATUS_BUFFER_TOO_SMALL && st != STATUS_BUFFER_OVERFLOW) {
        ZwClose(hKey);
        WhitelistFree();
        return STATUS_SUCCESS;
    }

    PKEY_VALUE_PARTIAL_INFORMATION info =
        (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, need, TAG);
    if (!info) {
        ZwClose(hKey);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    st = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, info, need, &need);
    ZwClose(hKey);

    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(info, TAG);
        return st;
    }

    if (info->Type != REG_MULTI_SZ || info->DataLength < sizeof(WCHAR)) {
        ExFreePoolWithTag(info, TAG);
        WhitelistFree();
        return STATUS_SUCCESS;
    }

    PWSTR p = (PWSTR)info->Data;
    ULONG count = 0;
    while (*p) {
        count++;
        p += (wcslen(p) + 1);
    }

    UINT64* items = NULL;
    ULONG okCount = 0;

    if (count > 0) {
        items = (UINT64*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(UINT64) * count, TAG);
        if (!items) {
            ExFreePoolWithTag(info, TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        p = (PWSTR)info->Data;
        while (*p) {
            UINT64 v = 0;
            if (HexToU64(p, &v)) {
                items[okCount++] = v;
            }
            p += (wcslen(p) + 1);
        }
    }

    ExFreePoolWithTag(info, TAG);

    ExAcquirePushLockExclusive(&gWl.Lock);
    if (gWl.Items) ExFreePoolWithTag(gWl.Items, TAG);
    gWl.Items = items;
    gWl.Count = okCount;
    ExReleasePushLockExclusive(&gWl.Lock);

    return STATUS_SUCCESS;
}

static BOOLEAN WhitelistContains(_In_ UINT64 h)
{
    BOOLEAN found = FALSE;
    ExAcquirePushLockShared(&gWl.Lock);
    for (ULONG i = 0; i < gWl.Count; i++) {
        if (gWl.Items[i] == h) { found = TRUE; break; }
    }
    ExReleasePushLockShared(&gWl.Lock);
    return found;
}

static NTSTATUS SendIoctlSync(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG IoControlCode,
    _In_opt_ PVOID InBuf,
    _In_ ULONG InLen,
    _Out_writes_bytes_opt_(OutLen) PVOID OutBuf,
    _In_ ULONG OutLen,
    _Out_ ULONG* BytesReturned
)
{
    if (BytesReturned) *BytesReturned = 0; 

    KEVENT ev;
    KeInitializeEvent(&ev, NotificationEvent, FALSE);

    IO_STATUS_BLOCK iosb;
    RtlZeroMemory(&iosb, sizeof(iosb));

    PIRP irp = IoBuildDeviceIoControlRequest(
        IoControlCode, DeviceObject,
        InBuf, InLen,
        OutBuf, OutLen,
        FALSE,
        &ev,
        &iosb
    );
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS st = IoCallDriver(DeviceObject, irp);
    if (st == STATUS_PENDING) {
        KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
        st = iosb.Status;
    }

    if (BytesReturned) *BytesReturned = (ULONG)iosb.Information;
    return st;
}

static NTSTATUS QueryUsbAndSerial(
    _In_ PFLT_VOLUME Volume,
    _Out_ BOOLEAN* IsUsb,
    _Out_writes_(SerialCch) PWSTR SerialOut,
    _In_ ULONG SerialCch
)
{
    if (IsUsb) *IsUsb = FALSE;
    if (SerialOut && SerialCch) SerialOut[0] = L'\0';

    PDEVICE_OBJECT disk = NULL;
    NTSTATUS st = FltGetDiskDeviceObject(Volume, &disk);
    if (!NT_SUCCESS(st)) return st;

    STORAGE_PROPERTY_QUERY q;
    RtlZeroMemory(&q, sizeof(q));
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;

    UCHAR buf[1024];
    RtlZeroMemory(buf, sizeof(buf));

    ULONG bytes = 0;

    st = SendIoctlSync(disk, IOCTL_STORAGE_QUERY_PROPERTY,
        &q, sizeof(q),
        buf, sizeof(buf),
        &bytes);

    ObDereferenceObject(disk);

    if (!NT_SUCCESS(st)) return st;
    if (bytes < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return STATUS_INFO_LENGTH_MISMATCH;

    PSTORAGE_DEVICE_DESCRIPTOR d = (PSTORAGE_DEVICE_DESCRIPTOR)buf;
    if (IsUsb) *IsUsb = (d->BusType == BusTypeUsb) ? TRUE : FALSE;

    if (SerialOut && SerialCch && d->SerialNumberOffset &&
        d->SerialNumberOffset < bytes)
    {
        PCSTR s = (PCSTR)(buf + d->SerialNumberOffset);

        ANSI_STRING a;
        UNICODE_STRING u;

        RtlInitAnsiString(&a, s);
        u.Buffer = SerialOut;
        u.Length = 0;
        u.MaximumLength = (USHORT)(SerialCch * sizeof(WCHAR));

        st = RtlAnsiStringToUnicodeString(&u, &a, FALSE);
        if (NT_SUCCESS(st)) {
            SerialOut[u.Length / sizeof(WCHAR)] = L'\0';
            NormalizeSerial(SerialOut);
        }
        else {
            SerialOut[0] = L'\0';
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS SetCtx(_In_ PCFLT_RELATED_OBJECTS FltObjects, BOOLEAN isUsb, BOOLEAN allowed, UINT64 serialHash)
{
    PCTX ctx = NULL;
    NTSTATUS st = FltAllocateContext(
        gFilter,
        FLT_INSTANCE_CONTEXT,
        sizeof(CTX),
        PagedPool,
        (PFLT_CONTEXT*)&ctx
    );
    if (!NT_SUCCESS(st)) return st;

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->IsUsb = isUsb;
    ctx->Allowed = allowed;
    ctx->SerialHash = serialHash;

    st = FltSetInstanceContext(
        FltObjects->Instance,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        ctx,
        NULL
    );

    FltReleaseContext(ctx);
    return st;
}

static FLT_PREOP_CALLBACK_STATUS PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
)
{
    if (CompletionContext) *CompletionContext = NULL; 

    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PCTX ctx = NULL;
    NTSTATUS st = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT*)&ctx);
    if (!NT_SUCCESS(st) || !ctx) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (ctx->IsUsb && !ctx->Allowed) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        FltReleaseContext(ctx);
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseContext(ctx);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    BOOLEAN isUsb = FALSE;
    WCHAR serial[128] = { 0 };

    NTSTATUS st = QueryUsbAndSerial(FltObjects->Volume, &isUsb, serial, ARRAYSIZE(serial));
    if (!NT_SUCCESS(st)) {
        isUsb = FALSE;      
        serial[0] = L'\0';
    }

    UINT64 h = 0;
    BOOLEAN allowed = TRUE;

    if (isUsb) {
        if (serial[0] == L'\0') {
            allowed = FALSE;  
        }
        else {
            h = HashSerial(serial);
            allowed = WhitelistContains(h);
        }
    }

    return SetCtx(FltObjects, isUsb, allowed, h);
}

static NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    WhitelistFree();

    if (gFilter) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return STATUS_SUCCESS;
}

static const FLT_CONTEXT_REGISTRATION CtxReg[] = {
    { FLT_INSTANCE_CONTEXT, 0, NULL, sizeof(CTX), TAG },
    { FLT_CONTEXT_END }
};

static const FLT_OPERATION_REGISTRATION Ops[] = {
    { IRP_MJ_CREATE, 0, PreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION Reg = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    CtxReg,
    Ops,
    Unload,
    InstanceSetup,
    NULL, NULL, NULL,
    NULL, NULL, NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    ExInitializePushLock(&gWl.Lock);
    (VOID)ReadWhitelistFromRegistry(RegistryPath);

    NTSTATUS st = FltRegisterFilter(DriverObject, &Reg, &gFilter);
    if (!NT_SUCCESS(st)) return st;

    st = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(st)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return st;
    }

    return STATUS_SUCCESS;
}
