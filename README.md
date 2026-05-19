# ADTools

PowerShell GUI for on-premises Active Directory helpdesk tasks: user lookup, computer lookup, AD notes, password reset, account unlock, and lockout diagnostics.

**Repository:** [github.com/Rock-Valley-College/ADTools](https://github.com/Rock-Valley-College/ADTools)

## Download

Get the latest packaged copy from **[Releases](https://github.com/Rock-Valley-College/ADTools/releases)**.

1. Open the newest release.
2. Download `ADTools-vX.Y.Z.zip`.
3. Extract to a folder (e.g. `C:\Tools\ADTools`).
4. Keep `ADTools.ps1` and `config.json` in the same folder.

## Requirements

- Domain-joined Windows PC
- PowerShell 5.1 or later
- RSAT **Active Directory** module (`Rsat.ActiveDirectory.DS-LDS.Tools`)
- AD rights to manage target users/computers and update notes where needed (delegation applies)
- Security event log read access on DCs for lockout diagnostics (Domain Admin or delegated Event Log Reader)

Install RSAT (elevated PowerShell):

```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

## Run

```powershell
cd C:\Tools\ADTools
Unblock-File .\ADTools.ps1   # once, if downloaded from the internet
.\ADTools.ps1
```

If the window flashes and closes, run with STA explicitly (required for WinForms):

```powershell
powershell -STA -File .\ADTools.ps1
```

To run the latest script directly from GitHub without downloading the zip:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -STA -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; irm https://raw.githubusercontent.com/Rock-Valley-College/ADTools/main/ADTools.ps1 | iex"
```

Remote runs use the built-in defaults from `ADTools.ps1`. To customize settings with `config.json`, download the release zip and run the local copy.

Startup errors are also written to `ADTools-startup.log` beside the script (or in `%TEMP%`).

The app opens even when the domain is unreachable (for example, off VPN). AD actions show a status message until you are connected. Install the RSAT Active Directory module on the PC; domain-joined is recommended when you run lookups and resets.

**Note:** The script is saved as ASCII-only (UTF-8 with BOM) so PowerShell 5.1 on any Windows locale parses it correctly. The UI uses a standard light grey theme so text stays readable regardless of Windows dark/light mode.

## Computer lookup

The **Computer** tab helps helpdesk staff quickly verify an AD computer object. Search by computer name with or without the trailing `$`.

It shows OU path, DNS hostname, IP address from AD/DNS, operating system, last logon, password last set, managed-by, description/location, and computer group memberships. Use **Copy Summary** to paste the key details into a ticket.

## AD notes

The **User** and **Computer** tabs can view and update the object's AD **Notes** field (`info` attribute). Use it for helpdesk context such as known lockout causes, stale device notes, or ticket references. The existing **Refresh** buttons pull the latest values back from AD.

## Configuration

Edit `config.json` next to the script:

| Setting | Default | Description |
|---------|---------|-------------|
| `MinPasswordLength` | 16 | Minimum length for reset passwords |
| `TempPasswordLength` | 16 | Length of generated temporary passwords (built-in **New** button) |

The built-in generator meets AD complexity rules. The Quarry has a temp password generator for easy over the phone passwords; copy one into the password field, then **Reset Password**.

Restart the app after changing config.

## Troubleshooting: temp password / cannot change password

After a user lookup, **Account Details** shows fields that map to common helpdesk cases (including reports where a temp password works but change-password fails):

| Field | What it means |
|-------|----------------|
| **Cannot Change Pwd** | AD account flag *User cannot change password*. Must be **No**. |
| **Must Change Pwd** | *User must change password at next logon*. ADTools sets this when you use **Reset Password** here. Azure-only temp passwords may not set this on-prem. |
| **SELF Change Pwd** | **SELF** extended right *Change password* (same as ADUC Security tab). **Allow (explicit)** / **Allow (inherited)** = user can change their own password. **Not allowed** or **DENIED** = fix in ADUC (Security > SELF > Allow *Change password*). |

**ADTools reset (on-prem):** `Set-ADAccountPassword -Reset` and `Set-ADUser -ChangePasswordAtLogon $true`. User should change password on a **domain-joined PC** (Ctrl+Alt+Del), not only in a browser tab that may show session errors (e.g. 50133).

**Find accounts with the “cannot change” flag** (adjust search base):

```powershell
Get-ADUser -Filter 'CannotChangePassword -eq $true' -SearchBase 'OU=Students,DC=yourdomain,DC=edu' -Properties SamAccountName, DistinguishedName |
  Select-Object SamAccountName, DistinguishedName
```

SELF permissions require per-object ACL review in ADUC or a custom audit script; ADTools checks the signed-in user on lookup.

## Publishing a new release (maintainers)

1. Update `$SCRIPT_VERSION` in `ADTools.ps1` to match the tag.
2. Commit and push to `main`.
3. Create and push a version tag (triggers the release workflow):

```powershell
git tag v2.1.0
git push origin v2.1.0
```

The workflow builds `ADTools-v2.1.0.zip` and attaches it to the GitHub Release automatically.

## License

See repository settings for license information.
