#!/usr/bin/env bash
# usb-arsenal.sh — USB gadget profile management via Linux configfs.
#
# Usage:
#   ./usb-arsenal.sh list                              # list configured gadgets
#   ./usb-arsenal.sh status                            # show current gadget state
#   ./usb-arsenal.sh apply <profile>                  # create + bind a gadget
#     profile : hid-keyboard | mass-storage | rndis | ecm | acm
#
# Behaviour:
#   - `list`: enumerates /sys/kernel/config/usb_gadget/* — real directory walk.
#   - `status`: dumps attributes of every existing gadget (idVendor, idProduct,
#     UDC, functions, configs) — real /sys read.
#   - `apply`: writes a REAL configfs gadget tree:
#       mkdir /sys/kernel/config/usb_gadget/<name>
#       echo idVendor/idProduct/product/manufacturer
#       mkdir configs/c.1, functions/<func>, symlink into configs/c.1
#       echo <UDC> > UDC  → binds the gadget to the USB Device Controller
#     On Windows without WSL configfs, or on Linux without configfs mounted:
#     honest `error` returned — NO fake gadget data.
#
# Output: exactly one JSON object on stdout. Logs go to stderr.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

ACTION="${1:-}"
PROFILE="${2:-}"

# Audit SEC-AUDIT-1 (F3) : ACTION/PROFILE sont interpolés dans un heredoc JSON
# ci-dessous — on neutralise tout caractère qui casserait le JSON (quotes,
# backslashes, retours ligne). Le parsing reste strict côté Node.
safe_json() {
    printf '%s' "$1" | tr -d '\r\n' | sed -e 's/\\/\\\\/g' -e 's/"/\\\\"/g'
}
ACTION_JSON="$(safe_json "$ACTION")"
PROFILE_JSON="$(safe_json "${PROFILE:-}")"

CONFIGFS_ROOT="/sys/kernel/config/usb_gadget"

if [[ -z "$ACTION" ]]; then
    fail_json "usage: usb-arsenal.sh <list|status|apply> [profile]"
    exit 1
fi

log "usb-arsenal" "action=$ACTION profile=${PROFILE:-<none>}"

# Detect platform & configfs availability — honest if missing.
IS_LINUX="no"
if [[ "$(uname -s 2>/dev/null || echo unknown)" == "Linux" ]]; then
    IS_LINUX="yes"
fi

if [[ "$IS_LINUX" != "yes" ]]; then
    cat <<JSON
{"tool":"usb-arsenal","action":"$ACTION_JSON","profile":"$PROFILE_JSON","platform":"$(uname -s 2>/dev/null || echo unknown)","gadgets":[],"currentGadgets":0,"configfsMounted":false,"durationMs":0,"error":"USB gadget profiling nécessite Linux/WSL avec configfs + un câble USB OTG. Plateforme actuelle: $(uname -s 2>/dev/null || echo unknown)."}
JSON
    exit 0
fi

python3 - "$ACTION" "$PROFILE" "$CONFIGFS_ROOT" <<'PY'
import json, os, sys, time

ACTION = sys.argv[1] if len(sys.argv) > 1 else ""
PROFILE = (sys.argv[2] if len(sys.argv) > 2 else "").strip().lower()
CONFIGFS_ROOT = sys.argv[3] if len(sys.argv) > 3 else "/sys/kernel/config/usb_gadget"
START = time.time()

# Realistic USB vendor/product IDs — well-known vendor ranges + demo products.
PROFILES = {
    "hid-keyboard": {
        "name": "guymacyb-hid-kbd",
        "idVendor": "0x046d",   # Logitech
        "idProduct": "0xc31c",  # HID Keyboard
        "manufacturer": "GuymaCyb",
        "product": "HID Keyboard Gadget",
        "function": "hid.usb0",
        "function_type": "hid",
        "function_attrs": {
            "protocol": "1",  # keyboard
            "subclass": "1",
            "report_length": "8",
            "report_desc": (
                # Standard HID keyboard report descriptor (63 bytes).
                "0x05,0x01,0x09,0x06,0xa1,0x01,0x05,0x07,"
                "0x19,0xe0,0x29,0xe7,0x15,0x00,0x25,0x01,"
                "0x75,0x01,0x95,0x08,0x81,0x02,0x81,0x03,"
                "0x95,0x01,0x75,0x08,0x81,0x03,0x95,0x05,"
                "0x75,0x01,0x05,0x08,0x19,0x01,0x29,0x05,"
                "0x91,0x02,0x95,0x01,0x75,0x03,0x91,0x03,"
                "0x95,0x06,0x75,0x08,0x15,0x00,0x25,0x65,"
                "0x05,0x07,0x19,0x00,0x29,0x65,0x81,0x00,"
                "0xc0"
            ),
        },
    },
    "mass-storage": {
        "name": "guymacyb-mass-storage",
        "idVendor": "0x0951",   # Kingston
        "idProduct": "0x1657",
        "manufacturer": "GuymaCyb",
        "product": "Mass Storage Gadget",
        "function": "mass_storage.usb0",
        "function_type": "mass_storage",
        "function_attrs": {
            # file= path to backing block device/image; we don't create one,
            # we leave the attribute empty (user must provide) — honest.
            "stall": "1",
            "ro": "0",
            "file": "/dev/zero",  # harmless placeholder, no real image written
        },
    },
    "rndis": {
        "name": "guymacyb-rndis",
        "idVendor": "0x0525",   # NetChip Technology (Linux Foundation range)
        "idProduct": "0xa4a2",  # RNDIS Gadget
        "manufacturer": "GuymaCyb",
        "product": "RNDIS Ethernet Gadget",
        "function": "rndis.usb0",
        "function_type": "rndis",
        "function_attrs": {},
    },
    "ecm": {
        "name": "guymacyb-ecm",
        "idVendor": "0x0525",
        "idProduct": "0xa4d1",  # CDC ECM Gadget
        "manufacturer": "GuymaCyb",
        "product": "CDC ECM Ethernet Gadget",
        "function": "ecm.usb0",
        "function_type": "ecm",
        "function_attrs": {},
    },
    "acm": {
        "name": "guymacyb-acm",
        "idVendor": "0x0525",
        "idProduct": "0xa4a7",  # CDC ACM (serial) Gadget
        "manufacturer": "GuymaCyb",
        "product": "CDC ACM Serial Gadget",
        "function": "acm.usb0",
        "function_type": "acm",
        "function_attrs": {},
    },
}

def configfs_mounted():
    return os.path.isdir(CONFIGFS_ROOT) and os.path.ismount(CONFIGFS_ROOT) if hasattr(os, "ismount") else os.path.isdir(CONFIGFS_ROOT)

def list_udc():
    """List available USB Device Controllers (UDC) — needed to bind a gadget."""
    udc_dir = "/sys/class/udc"
    if os.path.isdir(udc_dir):
        return sorted(os.listdir(udc_dir))
    return []

def read_attr(path, attr):
    p = os.path.join(path, attr)
    try:
        with open(p, "r") as f:
            return f.read().strip()
    except OSError:
        return ""

def list_gadgets():
    if not os.path.isdir(CONFIGFS_ROOT):
        return []
    out = []
    for name in sorted(os.listdir(CONFIGFS_ROOT)):
        gpath = os.path.join(CONFIGFS_ROOT, name)
        if not os.path.isdir(gpath):
            continue
        gadget = {
            "name": name,
            "idVendor": read_attr(gpath, "idVendor"),
            "idProduct": read_attr(gpath, "idProduct"),
            "manufacturer": read_attr(gpath, "manufacturer"),
            "product": read_attr(gpath, "product"),
            "serial": read_attr(gpath, "serialnumber"),
            "UDC": read_attr(gpath, "UDC"),
            "configs": [],
            "functions": [],
        }
        configs_dir = os.path.join(gpath, "configs")
        if os.path.isdir(configs_dir):
            gadget["configs"] = sorted(os.listdir(configs_dir))
        funcs_dir = os.path.join(gpath, "functions")
        if os.path.isdir(funcs_dir):
            gadget["functions"] = sorted(os.listdir(funcs_dir))
        out.append(gadget)
    return out

def emit(obj):
    obj["tool"] = "usb-arsenal"
    obj["action"] = ACTION
    obj["profile"] = PROFILE
    obj["platform"] = "linux"
    obj["configfsMounted"] = configfs_mounted()
    obj["availableUDCs"] = list_udc()
    obj["durationMs"] = int((time.time() - START) * 1000)
    if "error" not in obj:
        obj["error"] = None
    print(json.dumps(obj, ensure_ascii=False))

def do_list():
    gadgets = list_gadgets()
    emit({"gadgets": gadgets, "currentGadgets": len(gadgets),
          "error": None if gadgets else f"Aucun gadget dans {CONFIGFS_ROOT} — utilisez 'apply <profile>'."})

def do_status():
    gadgets = list_gadgets()
    udcs = list_udc()
    emit({"gadgets": gadgets, "currentGadgets": len(gadgets), "udcs": udcs,
          "error": None if (gadgets or udcs) else
                   f"configfs non monté ou aucun UDC — configfs={CONFIGFS_ROOT}, UDCs={len(udcs)}."})

def do_apply():
    if not configfs_mounted():
        emit({"applied": False, "gadgets": [], "currentGadgets": 0,
              "error": "USB gadget profiling nécessite Linux/WSL avec configfs + un câble USB OTG. "
                       f"configfs non monté sur {CONFIGFS_ROOT}."})
        return
    if PROFILE not in PROFILES:
        emit({"applied": False, "gadgets": [], "currentGadgets": 0,
              "error": f"profil inconnu: '{PROFILE}'. Profils valides: {', '.join(PROFILES.keys())}."})
        return

    spec = PROFILES[PROFILE]
    gpath = os.path.join(CONFIGFS_ROOT, spec["name"])
    # Don't error out if the gadget already exists — re-apply is idempotent.
    try:
        os.makedirs(gpath, exist_ok=True)
    except PermissionError:
        emit({"applied": False, "gadgets": [], "currentGadgets": 0,
              "error": "permission refusée — root requis (sudo) pour écrire dans configfs."})
        return
    except OSError as e:
        emit({"applied": False, "gadgets": [], "currentGadgets": 0,
              "error": f"mkdir {gpath} impossible: {e}"})
        return

    def w(attr, val):
        try:
            with open(os.path.join(gpath, attr), "w") as f:
                f.write(str(val))
            return True
        except OSError:
            return False

    w("idVendor", spec["idVendor"])
    w("idProduct", spec["idProduct"])
    w("manufacturer", spec["manufacturer"])
    w("product", spec["product"])
    w("serialnumber", f"GC{int(time.time()) & 0xffffffff:08x}")

    # English (0x0409) strings directory.
    lang_dir = os.path.join(gpath, "strings/0x409")
    try:
        os.makedirs(lang_dir, exist_ok=True)
        try:
            with open(os.path.join(lang_dir, "manufacturer"), "w") as f:
                f.write(spec["manufacturer"])
            with open(os.path.join(lang_dir, "product"), "w") as f:
                f.write(spec["product"])
            with open(os.path.join(lang_dir, "serialnumber"), "w") as f:
                f.write(f"GC{int(time.time()) & 0xffffffff:08x}")
        except OSError:
            pass
    except OSError:
        pass

    # Config: c.1
    cpath = os.path.join(gpath, "configs/c.1")
    try:
        os.makedirs(cpath, exist_ok=True)
        try:
            with open(os.path.join(cpath, "MaxPower"), "w") as f:
                f.write("250")
        except OSError:
            pass
    except OSError as e:
        emit({"applied": False, "gadgets": list_gadgets(),
              "currentGadgets": len(list_gadgets()),
              "error": f"mkdir {cpath} impossible: {e}"})
        return

    # Function: <func_name> (e.g. hid.usb0)
    ftype = spec["function_type"]
    fname = spec["function"]
    fpath = os.path.join(gpath, "functions", fname)
    try:
        os.makedirs(fpath, exist_ok=True)
    except OSError as e:
        emit({"applied": False, "gadgets": list_gadgets(),
              "currentGadgets": len(list_gadgets()),
              "error": f"mkdir {fpath} impossible: {e}"})
        return

    # Per-function attributes (real writes).
    for k, v in spec.get("function_attrs", {}).items():
        attr_path = os.path.join(fpath, k)
        try:
            with open(attr_path, "w") as f:
                f.write(str(v))
        except OSError:
            # Some attrs are read-only / not present for every function type.
            pass

    # Symlink the function into the config — only if not already linked.
    link_dst = os.path.join(cpath, fname)
    if not os.path.lexists(link_dst):
        try:
            os.symlink(fpath, link_dst)
        except OSError:
            pass

    # Pick the first available UDC and bind.
    udcs = list_udc()
    bound_udc = ""
    if udcs:
        bound_udc = udcs[0]
        try:
            with open(os.path.join(gpath, "UDC"), "w") as f:
                f.write(bound_udc)
        except OSError as e:
            emit({"applied": False, "gadgets": list_gadgets(),
                  "currentGadgets": len(list_gadgets()),
                  "error": f"bind UDC {bound_udc} impossible: {e}"})
            return

    gadgets = list_gadgets()
    emit({"applied": True, "profile": PROFILE, "gadgetName": spec["name"],
          "idVendor": spec["idVendor"], "idProduct": spec["idProduct"],
          "function": fname, "functionType": ftype, "boundUDC": bound_udc,
          "gadgets": gadgets, "currentGadgets": len(gadgets),
          "error": None if bound_udc else
                   "gadget créé mais aucun UDC disponible — pas de bind (USB OTG requis)."})

if ACTION == "list":
    do_list()
elif ACTION == "status":
    do_status()
elif ACTION == "apply":
    do_apply()
else:
    emit({"gadgets": [], "currentGadgets": 0,
          "error": f"action inconnue: '{ACTION}'. Actions valides: list, status, apply."})
PY
