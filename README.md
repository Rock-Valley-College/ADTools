# ADTools

PowerShell GUI for on-premises Active Directory helpdesk tasks: user lookup, computer lookup, AD notes, account unlock/enable, and lockout diagnostics.

**Repository:** [github.com/Rock-Valley-College/ADTools](https://github.com/Rock-Valley-College/ADTools)

## Download

Get the latest packaged copy from **[Releases](https://github.com/Rock-Valley-College/ADTools/releases)**.

1. Open the newest release.
2. Download `ADTools-vX.Y.Z.zip`.
3. Extract to a folder (e.g. `C:\Tools\ADTools`).
4. Run `ADTools.ps1` from the extracted folder.

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

Startup errors are also written to `ADTools-startup.log` beside the script (or in `%TEMP%`).

The app opens even when the domain is unreachable (for example, off VPN). AD actions show a status message until you are connected. Install the RSAT Active Directory module on the PC; domain-joined is recommended when you run lookups.

**Note:** The script is saved as ASCII-only (UTF-8 with BOM) so PowerShell 5.1 on any Windows locale parses it correctly. The UI uses a standard light grey theme so text stays readable regardless of Windows dark/light mode.

## Computer lookup

The **Computer** tab helps helpdesk staff quickly verify an AD computer object. Search by computer name with or without the trailing `$`.

It shows OU path, DNS hostname, IP address from AD/DNS, physical location (AD `Location` attribute), inactive/stale hint (configurable via `StaleComputerDays` in `config.json`), operating system, last logon, password last set, managed-by, description, computer group memberships, and **LAPS** local admin password via `Get-LapsADPassword` when the Windows **LAPS** PowerShell module is installed (falls back to legacy AD attributes if not). Use **Copy Summary** to paste the key details into a ticket.

## User lookup

The **User** tab accepts **samAccountName** or **email / UPN**. It shows contact fields (manager, office, phone), lockout-related counts and times, account expiration, last modified, password flags, **extension attributes** used for provisioning (labels in `config.json`; `extensionAttribute10` defaults to **Personal email**), groups, and AD notes. Use **Copy Summary** to paste into a ticket.

Example `config.json` extension labels:

```json
"UserExtensionAttributes": {
  "extensionAttribute10": "Personal email",
  "extensionAttribute3": "Student ID"
}
```

Restart ADTools after editing `config.json`.

## AD notes

The **User** and **Computer** tabs can view and update the object's AD **Notes** field (`info` attribute). Saved notes add or replace a top `Notes last updated by ... on YYYY-MM-DD` line, then write the note body to AD. Use notes for helpdesk context such as known lockout causes, stale device notes, or ticket references. The existing **Refresh** buttons pull the latest values back from AD.

## Publishing a new release (maintainers)

Pushing to `main` automatically creates the next patch release. The workflow reads the latest `vX.Y.Z` tag, increments the patch version, updates `$SCRIPT_VERSION`, commits that version bump, tags it, and publishes a GitHub Release.

For a manual minor/major release, include `[skip tag]` in the commit message, push to `main`, then create and push the desired version tag:

```powershell
git tag v2.4.0
git push origin v2.4.0
```

The tag workflow builds `ADTools-vX.Y.Z.zip` and attaches it to the GitHub Release automatically.

## License

See repository settings for license information.
