<#
.SYNOPSIS
  Copy (or junction) skills from this repo into a Claude Code skills directory.

.EXAMPLE
  .\scripts\install.ps1                       # all skills -> $HOME\.claude\skills
  .\scripts\install.ps1 -Project              # all skills -> .\.claude\skills
  .\scripts\install.ps1 -Link                 # junction instead of copy
  .\scripts\install.ps1 ioc-extraction phishing-analysis

.NOTES
  Prefer the plugin route when you can (see README). This script is for teams that vendor
  skills into their own repos or run without marketplace access.
#>
[CmdletBinding()]
param(
  [Parameter(ValueFromRemainingArguments = $true)] [string[]] $Skills,
  [switch] $Project,
  [switch] $Link,
  [string] $Dest
)

$Here = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Dest) {
  if ($Project) { $Dest = Join-Path (Get-Location) ".claude\skills" }
  else { $Dest = Join-Path $HOME ".claude\skills" }
}
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

if (-not $Skills -or $Skills.Count -eq 0) {
  $Skills = Get-ChildItem -Directory (Join-Path $Here "skills") | Select-Object -ExpandProperty Name
}

foreach ($name in $Skills) {
  $src = Join-Path $Here "skills\$name"
  if (-not (Test-Path (Join-Path $src "SKILL.md"))) {
    Write-Warning "skip: $name (no SKILL.md)"
    continue
  }
  $target = Join-Path $Dest $name
  if (Test-Path $target) { Remove-Item -Recurse -Force $target }
  if ($Link) {
    New-Item -ItemType Junction -Path $target -Target $src | Out-Null
  } else {
    Copy-Item -Recurse -Path $src -Destination $target
  }
  Write-Host "installed: $name -> $target"
}
