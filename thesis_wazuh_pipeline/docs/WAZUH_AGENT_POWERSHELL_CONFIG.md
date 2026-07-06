# Wazuh Agent Configuration for PowerShell ScriptBlock Logging

Use this on the Windows 11 lab VM.

## Enable ScriptBlock Logging

Run PowerShell as Administrator:

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name EnableScriptBlockLogging `
  -Value 1 `
  -Type DWord
```

Verify that event ID 4104 appears after running a test command:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5 |
  Select-Object TimeCreated, Id, ProviderName, Message
```

## Configure Wazuh Agent EventChannel Collection

Edit the Wazuh agent configuration on Windows:

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Add this inside `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the Wazuh agent:

```powershell
Restart-Service WazuhSvc
```

## Baseline Principle

For the first experiment, do not add custom Wazuh rules. Use only the standard
Wazuh ruleset. This creates the baseline for the thesis comparison.

Later experiments can add custom Wazuh rules and repeat the same dataset.
