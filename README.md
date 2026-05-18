# ADTools

PowerShell GUI for on-premises Active Directory helpdesk tasks: user lookup, password reset, account unlock, and lockout diagnostics.

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
- AD rights to manage target users (delegation applies)
- Security event log read access on DCs for lockout diagnostics (Domain Admin or delegated Event Log Reader)

Install RSAT (elevated PowerShell):

```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

## Run

```powershell
cd C:\Tools\ADTools
.\ADTools.ps1
```

## Configuration

Edit `config.json` next to the script:

| Setting | Default | Description |
|---------|---------|-------------|
| `MinPasswordLength` | 16 | Minimum length for reset passwords |
| `TempPasswordLength` | 16 | Length of generated temporary passwords |

Restart the app after changing config.

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
