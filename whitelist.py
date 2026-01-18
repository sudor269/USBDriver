import sys
import winreg
from typing import List

SERVICE = "MyDriver1"
VALUE_NAME = "WhitelistHashes"

FNV_OFFSET = 1469598103934665603
FNV_PRIME  = 1099511628211

def normalize_serial(s: str) -> str:
    s = (s or "").strip()
    if "&" in s:
        s = s.split("&", 1)[0]
    return s.strip().upper()

def fnv1a64_utf16le(s: str) -> int:
    b = s.encode("utf-16le", errors="ignore")
    h = FNV_OFFSET
    for byte in b:
        h ^= byte
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

def hash_hex(serial: str) -> str:
    n = normalize_serial(serial)
    h = fnv1a64_utf16le(n)
    return f"{h:016X}"

def reg_path(service: str) -> str:
    return rf"SYSTEM\CurrentControlSet\Services\{service}\Parameters"

def open_or_create_params_key(service: str, access: int):
    path = reg_path(service)
    return winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, access)

def read_multisz(service: str) -> List[str]:
    with open_or_create_params_key(service, winreg.KEY_READ) as k:
        try:
            val, typ = winreg.QueryValueEx(k, VALUE_NAME)
        except FileNotFoundError:
            return []
        if typ != winreg.REG_MULTI_SZ:
            raise RuntimeError(f"{VALUE_NAME} exists but is not REG_MULTI_SZ")
        return [x.strip().upper() for x in val if x and x.strip()]

def write_multisz(service: str, items: List[str]) -> None:
    items = sorted(set([x.strip().upper() for x in items if x and x.strip()]))
    with open_or_create_params_key(service, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_MULTI_SZ, items)

def cmd_list(service: str):
    items = read_multisz(service)
    print(f"[{service}] {VALUE_NAME} ({len(items)} items):")
    for s in items:
        print(" ", s)

def cmd_add(service: str, serial: str):
    h = hash_hex(serial)
    items = read_multisz(service)
    if h in items:
        print("Already exists:", h)
        return
    items.append(h)
    write_multisz(service, items)
    print("Added:", h)
    print("From serial:", normalize_serial(serial))

def cmd_remove(service: str, hexhash: str):
    hexhash = (hexhash or "").strip().upper()
    items = read_multisz(service)
    new_items = [x for x in items if x != hexhash]
    write_multisz(service, new_items)
    print("Removed:", hexhash)

def cmd_hash(serial: str):
    print("Normalized:", normalize_serial(serial))
    print("Hash:", hash_hex(serial))

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python whitelist.py list [ServiceName]")
        print("  python whitelist.py add <serial_or_pnp_tail> [ServiceName]")
        print("  python whitelist.py remove <16HEXHASH> [ServiceName]")
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "list":
        service = sys.argv[2] if len(sys.argv) >= 3 else SERVICE
        cmd_list(service)

    elif cmd == "add":
        if len(sys.argv) < 3:
            print("add requires serial string")
            sys.exit(1)
        serial = sys.argv[2]
        service = sys.argv[3] if len(sys.argv) >= 4 else SERVICE
        cmd_add(service, serial)

    elif cmd == "remove":
        if len(sys.argv) < 3:
            print("remove requires 16-hex hash")
            sys.exit(1)
        h = sys.argv[2]
        service = sys.argv[3] if len(sys.argv) >= 4 else SERVICE
        cmd_remove(service, h)

    else:
        print("Unknown command:", cmd)
        sys.exit(1)

if __name__ == "__main__":
    main()
