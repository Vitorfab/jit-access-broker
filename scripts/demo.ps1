# Scripted demo of jit-access-broker. Uses a temporary database and audit log (not in the repo).
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$db = Join-Path $env:TEMP "jit-demo.db"
$audit = Join-Path $env:TEMP "jit-demo-audit.jsonl"
Remove-Item $db, $audit -ErrorAction SilentlyContinue

function Section([string]$Title) { Write-Host "`n== $Title" -ForegroundColor Cyan }
function Jb { uv run jit-broker --db $db @args }

Section "alice asks for db-admin (two approvers required)"
Jb request --as alice --role db-admin --minutes 60 --justification "Demo: simulated database maintenance" --ticket DEMO-1
Section "access before approval (expect DENIED)"
Jb check --as alice --role db-admin
Section "alice is not an approver (expect refusal)"
Jb approve 1 --as alice --reason "Approving myself"
Section "first approval (carol)"
Jb approve 1 --as carol --reason "First approval"
Section "carol again (expect refusal)"
Jb approve 1 --as carol --reason "Trying twice"
Section "second approval (carlos)"
Jb approve 1 --as carlos --reason "Second approval"
Section "access after approval (expect ALLOWED)"
Jb check --as alice --role db-admin
Section "carol tries to revoke (expect refusal, admin only)"
Jb revoke 1 --as carol
Section "arthur revokes the grant"
Jb revoke 1 --as arthur
Section "access after revocation (expect DENIED)"
Jb check --as alice --role db-admin
Section "audit log verification"
Jb audit verify
Section "refused attempts recorded in the log"
Select-String -Path $audit -Pattern '"event":"action_refused"' | ForEach-Object { $_.Line }

Remove-Item $db, $audit -ErrorAction SilentlyContinue
exit 0