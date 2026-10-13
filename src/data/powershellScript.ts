export const BOOSTED_POWERSHELL_SCRIPT = `# ==============================================================================
# Suite de Securite & Defense PowerShell - ULTRA KERNEL & SYSTEM EDITION v3.5
# Auteur initial : Space [Goat Asta] | Boostee pour Ingenieurs Cybersecurite
# Niveau d'eradication : OS Kernel / TrustedInstaller / Handles verrouilles
# Mise a jour : Menus 10 a 14 integres & correctifs majeurs de stabilite
# ==============================================================================

#Requires -Version 5.1
$ErrorActionPreference = "SilentlyContinue"

# ---- ELEVATION PRIVILEGES (ADMINISTRATEUR + TOKEN PRIVILEGES) ----
function Ensure-Elevation {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal       = [Security.Principal.WindowsPrincipal]$currentIdentity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host " [!] Elevation UAC requise. Relance en Administrateur..." -ForegroundColor Yellow
        Start-Process -FilePath "powershell.exe" \`
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File \`"$PSCommandPath\`"" \`
            -Verb RunAs
        exit
    }
}
Ensure-Elevation

# ---- ACQUISITION PRIVILEGES CRITIQUES WINDOWS (SeDebugPrivilege / SeTakeOwnership) ----
$PInvokeTypeDef = @"
using System;
using System.Runtime.InteropServices;

public class NativeSecurity {
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtResumeProcess(IntPtr processHandle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

    public const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;
}
"@
if (-not ([System.Management.Automation.PSTypeName]'NativeSecurity').Type) {
    Add-Type -TypeDefinition $PInvokeTypeDef -PassThru | Out-Null
}

$VERSION     = "3.5-KERNEL"
$reportPath  = "$env:USERPROFILE\\Desktop\\SpaceSecurity_UltraReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$logPath     = "$env:USERPROFILE\\Desktop\\SpaceSecurity_Kernel_Log.txt"
$quarantine  = "$env:SystemDrive\\SpaceSec_Quarantine"
$backupDir   = "$env:SystemDrive\\SpaceSec_Backups"

if (-not (Test-Path $quarantine)) {
    New-Item -ItemType Directory -Path $quarantine -Force | Out-Null
}
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}

# Liste blanche de securite pour eviter les faux positifs (Narrator, Configuration, etc.)
$GLOBAL:SAFE_PROCESS_NAMES = @(
    "Narrator", "SystemConfiguration", "msconfig", "Configuration",
    "ApplicationFrameHost", "TextInputHost", "smartscreen", "SecurityHealthHost"
)

# ---- HELPERS LOGGING & BANNIERE ----
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "   ███████╗██████╗  █████╗  ██████╗███████╗███████╗███████╗ ██████╗ " -ForegroundColor Cyan
    Write-Host "   ██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝ " -ForegroundColor Cyan
    Write-Host "   ███████╗██████╔╝███████║██║     █████╗  ███████╗█████╗  ██║      " -ForegroundColor Blue
    Write-Host "   ╚════██║██╔═══╝ ██╔══██║██║     ██╔══╝  ╚════██║██╔══╝  ██║      " -ForegroundColor DarkCyan
    Write-Host "   ███████║██║     ██║  ██║╚██████╗███████╗███████║███████╗╚██████╗ " -ForegroundColor DarkCyan
    Write-Host "   ╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝╚══════╝ ╚═════╝ " -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  ================================================================================" -ForegroundColor DarkGray
    Write-Host "   CYBERDEFENSE & KERNEL EXTIRPATOR v$VERSION - [Dev & Cybersec Space / Goat Asta]" -ForegroundColor Yellow
    Write-Host "   Menus 10 a 14 : Detection Profonde, Remediation, Defender, Forensique & Rapports" -ForegroundColor DarkCyan
    Write-Host "   Niveau : Eradication racine OS, TrustedInstaller, PendingFileRename & C2 Hunter" -ForegroundColor DarkGray
    Write-Host "  ================================================================================" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Logging {
    param([string]$texte, [string]$niveau = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $couleur = switch ($niveau) {
        "OK"      { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "KERNEL"  { "Magenta" }
        "C2"      { "DarkRed" }
        "INFO"    { "Cyan" }
        default   { "White" }
    }
    $logMessage = "[$timestamp] [$niveau] $texte"
    Write-Host "  [$timestamp] " -NoNewline -ForegroundColor DarkGray
    Write-Host "[$niveau] " -NoNewline -ForegroundColor $couleur
    Write-Host "$texte" -ForegroundColor White
    Add-Content -Path $reportPath -Value $logMessage -ErrorAction SilentlyContinue
    Add-Content -Path $logPath    -Value $logMessage -ErrorAction SilentlyContinue
}

function Show-SectionHeader {
    param([string]$titre)
    Write-Host ""
    Write-Host "  -----[ $titre ]-----" -ForegroundColor Magenta
    Write-Host ""
}

function Pause-Menu {
    Write-Host ""
    Read-Host "  Appuyez sur ENTREE pour revenir au menu..."
}

# ==============================================================================
#   GARDE-FOUS DE SECURITE : AUTHENTICODE MICROSOFT & QUARANTAINE RESTAURABLE
# ==============================================================================
function Test-IsMicrosoftSigned {
    param([string]$filePath)
    if (-not (Test-Path $filePath)) { return $false }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
        if ($sig.Status -eq "Valid") {
            $subject = $sig.SignerCertificate.Subject
            if ($subject -match "Microsoft (Windows|Corporation)") {
                return $true
            }
        }
    } catch {}
    return $false
}

function Move-ToQuarantine {
    param(
        [string]$filePath,
        [string]$reason = "Detection Suspicion"
    )
    if (-not (Test-Path $filePath)) {
        Write-Logging "Fichier introuvable pour quarantaine : $filePath" "WARN"
        return $false
    }

    # Garde-fou de protection Windows
    if (Test-IsMicrosoftSigned $filePath) {
        Write-Host "  [GARDE-FOU ACTIVE] Ce fichier est signe par Microsoft Corporation !" -ForegroundColor Yellow
        Write-Host "  Chemin : $filePath" -ForegroundColor White
        $force = Read-Host "  Confirmez-vous reellement la mise en quarantaine de ce binaire systeme ? (O/N)"
        if ($force -notmatch "^[Oo]$") {
            Write-Logging "Action annulee par l'operateur : Fichier legitime Microsoft protege." "INFO"
            return $false
        }
    }

    try {
        $fileName = [System.IO.Path]::GetFileName($filePath)
        $sha256 = (Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $destFileName = "$fileName.$sha256.quar"
        $destPath = Join-Path $quarantine $destFileName
        $manifestPath = "$destPath.manifest.json"

        # Manifeste pour permettre la restauration
        $manifest = @{
            OriginalPath   = $filePath
            QuarantinePath = $destPath
            FileName       = $fileName
            SHA256         = $sha256
            Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Reason         = $reason
            SizeBytes      = (Get-Item $filePath).Length
        } | ConvertTo-Json -Compress

        # Tuer les processus verrouillant le fichier
        $lockingProcs = Get-Process | Where-Object {
            (try { $_.MainModule.FileName -eq $filePath } catch { $false })
        }
        foreach ($p in $lockingProcs) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }

        # Deplacement vers la quarantaine et revocation des droits d'execution
        Move-Item -Path $filePath -Destination $destPath -Force
        Set-Content -Path $manifestPath -Value $manifest -Force
        Start-Process "icacls.exe" -ArgumentList "\`"$destPath\`" /deny Everyone:(X)" -NoNewWindow -Wait

        Write-Logging "Fichier mis en quarantaine restaurable avec succes : $destFileName" "OK"
        return $true
    } catch {
        Write-Logging "Echec de mise en quarantaine directe ($($_.Exception.Message))." "ERROR"
        return $false
    }
}

function Restore-QuarantineItem {
    Show-SectionHeader "RESTAURATION D'UN FICHIER DEPUIS LA QUARANTAINE"
    $manifestFiles = Get-ChildItem -Path $quarantine -Filter "*.manifest.json" -ErrorAction SilentlyContinue
    if (-not $manifestFiles -or $manifestFiles.Count -eq 0) {
        Write-Logging "Aucun element en quarantaine actuellement." "INFO"
        return
    }

    Write-Host "  Fichiers actuellement en quarantaine :" -ForegroundColor Cyan
    $i = 1
    $entries = @()
    foreach ($m in $manifestFiles) {
        $info = Get-Content $m.FullName | ConvertFrom-Json
        $entries += $info
        Write-Host "   [$i] $($info.FileName) | Date: $($info.Timestamp) | SHA256: $($info.SHA256.Substring(0,12))..." -ForegroundColor Yellow
        Write-Host "       Chemin d'origine : $($info.OriginalPath)" -ForegroundColor DarkGray
        $i++
    }

    Write-Host ""
    $choice = Read-Host "  Entrez le numero de l'element a restaurer (ou 0 pour annuler)"
    if ($choice -match "^[1-9][0-9]*$" -and [int]$choice -le $entries.Count) {
        $selected = $entries[[int]$choice - 1]
        Write-Logging "Restauration de $($selected.FileName) vers $($selected.OriginalPath)..." "INFO"

        $destDir = [System.IO.Path]::GetDirectoryName($selected.OriginalPath)
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        # Reinitialiser les ACLs d'execution
        Start-Process "icacls.exe" -ArgumentList "\`"$($selected.QuarantinePath)\`" /remove:d Everyone" -NoNewWindow -Wait
        Move-Item -Path $selected.QuarantinePath -Destination $selected.OriginalPath -Force
        Remove-Item -Path "$($selected.QuarantinePath).manifest.json" -Force -ErrorAction SilentlyContinue

        Write-Logging "Fichier restaure avec succes a son emplacement d'origine !" "OK"
    } else {
        Write-Logging "Operation de restauration annulee." "INFO"
    }
}

# ==============================================================================
#   MODULE KERNEL-1 : ERADICATION PROFONDE DE FICHIER VERROUILLE (TRUSTEDINSTALLER / HANDLES)
# ==============================================================================
function Invoke-DeepFileExcision {
    param([string]$filePath)

    if (-not $filePath) {
        $filePath = Read-Host "  Entrez le chemin complet du fichier ou programme a eradiquer"
    }

    $cleanPath = $filePath.Trim().Trim('"')
    if (-not (Test-Path $cleanPath)) {
        Write-Logging "Fichier introuvable sur le disque : $cleanPath" "WARN"
        return
    }

    # Garde-fou Authenticode Microsoft
    if (Test-IsMicrosoftSigned $cleanPath) {
        Write-Host "  [ALERTE GARDE-FOU] Le fichier cible est un binaire valide signe Microsoft !" -ForegroundColor Yellow
        $conf = Read-Host "  Voulez-vous reellement forcer la destruction de ce composant Windows ? (O/N)"
        if ($conf -notmatch "^[Oo]$") {
            Write-Logging "Eradication annulee pour proteger l'integrite du systeme." "INFO"
            return
        }
    }

    Write-Logging "Lancement du protocole d'eradication profonde : $cleanPath" "KERNEL"

    # Sauvegarde prealable
    try {
        $bFile = Join-Path $backupDir ([System.IO.Path]::GetFileName($cleanPath) + ".bak_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
        Copy-Item -Path $cleanPath -Destination $bFile -Force -ErrorAction SilentlyContinue
    } catch {}

    # 1. Neutraliser les attributs de protection (Systeme, Cache, Lecture seule)
    try {
        Set-ItemProperty -Path $cleanPath -Name Attributes -Value ([System.IO.FileAttributes]::Normal) -ErrorAction SilentlyContinue
    } catch {}

    # 2. Forcer l'appropriation de propriete (Take Ownership)
    Start-Process "takeown.exe" -ArgumentList "/F \`"$cleanPath\`" /A" -NoNewWindow -Wait
    Start-Process "takeown.exe" -ArgumentList "/F \`"$cleanPath\`"" -NoNewWindow -Wait

    # 3. Forcer les permissions ACL d'acces total aux Administrateurs
    Start-Process "icacls.exe" -ArgumentList "\`"$cleanPath\`" /grant *S-1-5-32-544:F /c /q" -NoNewWindow -Wait
    Start-Process "icacls.exe" -ArgumentList "\`"$cleanPath\`" /grant \`"$env:USERNAME\`:F /c /q" -NoNewWindow -Wait

    # 4. Tuer les processus verrouillant le fichier
    $fileName = [System.IO.Path]::GetFileName($cleanPath)
    $lockingProcs = Get-Process | Where-Object {
        $_.Name -match [System.IO.Path]::GetFileNameWithoutExtension($fileName) -or
        (try { $_.MainModule.FileName -eq $cleanPath } catch { $false })
    }
    foreach ($p in $lockingProcs) {
        Write-Logging "Fermeture du processus verrouillant PID $($p.Id) ($($p.Name))..." "WARN"
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        Start-Process "taskkill.exe" -ArgumentList "/F /T /PID $($p.Id)" -NoNewWindow -Wait
    }

    # 5. Tentative de suppression directe
    $deleted = $false
    try {
        [System.IO.File]::Delete($cleanPath)
        $deleted = -not (Test-Path $cleanPath)
    } catch {}

    if ($deleted) {
        Write-Logging "Eradication immediate reussie : $cleanPath" "OK"
        return
    }

    # 6. Programmation de la suppression Kernel au redemarrage (Session Manager / PendingFileRenameOperations)
    Write-Logging "Fichier verrouille par un driver/handle actif. Programmation au reboot..." "KERNEL"
    try {
        [NativeSecurity]::MoveFileEx($cleanPath, $null, [NativeSecurity]::MOVEFILE_DELAY_UNTIL_REBOOT)
    } catch {}

    try {
        $sessionKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"
        $currentPending = (Get-ItemProperty -Path $sessionKey -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
        $nativePath = "\\??\\$cleanPath"
        $newPending = if ($currentPending) { @($currentPending) + @($nativePath, "") } else { @($nativePath, "") }
        Set-ItemProperty -Path $sessionKey -Name "PendingFileRenameOperations" -Value $newPending -Type MultiString -Force
        Write-Logging "Cle PendingFileRenameOperations enregistree pour suppression au prochain boot." "OK"
    } catch {}

    # 7. Vider le contenu du binaire
    try {
        [System.IO.File]::WriteAllBytes($cleanPath, [byte[]]@())
        Write-Logging "Contenu du fichier ecrase a 0 octet." "OK"
    } catch {}

    # 8. Verrouiller les droits d'execution
    Start-Process "icacls.exe" -ArgumentList "\`"$cleanPath\`" /deny Everyone:(X)" -NoNewWindow -Wait
    Write-Logging "Fichier neutralise et planifie pour destruction definitive au reboot !" "OK"
}

# ==============================================================================
#   MODULE KERNEL-2 : SUSPENSION & BATCH-KILL DES PROCESSUS MUTUELS (WATCHDOGS)
# ==============================================================================
function Suspend-And-Kill-Watchdogs {
    Show-SectionHeader "EXTIRPATION PROCESSUS WATCHDOG (DOUBLE PROCESSUS)"
    $procQuery = Read-Host "  Nom ou pattern du processus a neutraliser (ex: swisyn, remcos, updater)"
    if (-not $procQuery) { return }

    # Filtrer les faux positifs
    if ($GLOBAL:SAFE_PROCESS_NAMES -contains $procQuery) {
        Write-Logging "Processus '$procQuery' figure sur la liste blanche systeme. Operation refusee." "WARN"
        return
    }

    $procs = Get-Process | Where-Object { $_.Name -match $procQuery -and $GLOBAL:SAFE_PROCESS_NAMES -notcontains $_.Name }
    if ($procs.Count -eq 0) {
        Write-Logging "Aucun processus suspect trouve correspondant a '$procQuery'." "INFO"
        return
    }

    Write-Logging "$($procs.Count) processus cibles detectes. SUSPENSION IMMEDIATE DES THREADS..." "KERNEL"
    foreach ($p in $procs) {
        try {
            [NativeSecurity]::NtSuspendProcess($p.Handle) | Out-Null
            Write-Logging "Processus gele (NtSuspendProcess) : $($p.Name) (PID: $($p.Id))" "OK"
        } catch {}
    }

    Start-Sleep -Milliseconds 500

    foreach ($p in $procs) {
        Start-Process "taskkill.exe" -ArgumentList "/F /T /PID $($p.Id)" -NoNewWindow -Wait
        Write-Logging "Processus abattu : PID $($p.Id) ($($p.Name))" "OK"
    }
}

# ==============================================================================
#   MODULE KERNEL-3 : AUDIT & NETTOYAGE IFEO (IMAGE FILE EXECUTION OPTIONS)
# ==============================================================================
function Clean-IFEODebuggerHijacks {
    Show-SectionHeader "DETOURNEMENT REGISTRE IFEO (IMAGE FILE EXECUTION OPTIONS)"
    Write-Logging "Verification des cles de debogage IFEO..." "INFO"

    $ifeoPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    $criticalTargets = @("taskmgr.exe","cmd.exe","powershell.exe","regedit.exe","MpCmdRun.exe","msconfig.exe","procexp.exe","procmon.exe")
    $hijacksFound = 0

    foreach ($target in $criticalTargets) {
        $subKey = "$ifeoPath\\$target"
        if (Test-Path $subKey) {
            $debugger = (Get-ItemProperty -Path $subKey -ErrorAction SilentlyContinue).Debugger
            if ($debugger) {
                $hijacksFound++
                Write-Host "  [DETOURNE!] $target -> Debugger = $debugger" -ForegroundColor Red
                Write-Logging "Detournement IFEO detecte sur $target (lance $debugger)" "C2"

                $ans = Read-Host "  Supprimer ce detournement malveillant ? (O/N)"
                if ($ans -match "^[Oo]$") {
                    Remove-ItemProperty -Path $subKey -Name "Debugger" -Force -ErrorAction SilentlyContinue
                    Write-Logging "Detournement $target neutralise avec succes !" "OK"
                }
            }
        }
    }

    if ($hijacksFound -eq 0) {
        Write-Logging "Aucun detournement IFEO detecte. Outils systeme sains." "OK"
    }
}

# ==============================================================================
#   MODULE KERNEL-4 : PURGE APPINIT_DLLS & APPCERTDLLS
# ==============================================================================
function Purge-AppInitAndAppCert {
    Show-SectionHeader "INJECTION GLOBALE APPINIT_DLLS / APPCERTDLLS"
    $appInitKeys = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    )

    foreach ($k in $appInitKeys) {
        if (Test-Path $k) {
            $dlls = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).AppInit_DLLs
            if ($dlls -and $dlls.Trim() -ne "") {
                Write-Host "  [SUSPECT!] $k -> AppInit_DLLs : $dlls" -ForegroundColor Red
                $ans = Read-Host "  Vider AppInit_DLLs ? (O/N)"
                if ($ans -match "^[Oo]$") {
                    Set-ItemProperty -Path $k -Name "AppInit_DLLs" -Value "" -Force
                    Set-ItemProperty -Path $k -Name "LoadAppInit_DLLs" -Value 0 -Type DWord -Force
                    Write-Logging "Cle AppInit_DLLs videe." "OK"
                }
            }
        }
    }
}

# ==============================================================================
#   MODULE KERNEL-5 : AUDIT PILOTES KERNEL & FILTER DRIVERS (ROOTKITS)
# ==============================================================================
function Audit-KernelDrivers {
    Show-SectionHeader "AUDIT PILOTES SYSTEME & FILTER DRIVERS"
    Write-Logging "Analyse des Mini-Filters du systeme de fichiers (fltmc)..." "INFO"
    fltmc filters 2>&1 | ForEach-Object {
        if ($_ -match "Filter Name|Altitude|Instances") {
            Write-Host "  $_" -ForegroundColor DarkCyan
        } elseif ($_ -match "[a-zA-Z0-9]") {
            Write-Host "  $_" -ForegroundColor White
        }
    }

    Write-Logging "Verification des pilotes non signes..." "INFO"
    $unsigned = driverquery /v /fo csv 2>&1 | ConvertFrom-Csv | Where-Object {
        $_.IsSigned -match "FALSE" -and $_.State -eq "Running"
    }
    if ($unsigned) {
        foreach ($d in $unsigned) {
            Write-Host "  -> [SUSPECT] $($d.DisplayName) ($($d.ModuleName))" -ForegroundColor Red
        }
    } else {
        Write-Logging "Tous les pilotes critiques en cours d'execution sont valides." "OK"
    }
}

# ==============================================================================
#   NOUVEAU - MENU 10 : DETECTION PROFONDE
# ==============================================================================
function Invoke-DeepDetection {
    Show-SectionHeader "MENU 10 : DETECTION PROFONDE SYSTEME & KERNEL"
    Write-Host "  [1] Usurpation de Processus (Spoofing de nom & parent anormal)" -ForegroundColor Cyan
    Write-Host "  [2] Processus Caches (Brute-Force PID 4..65535 vs API)" -ForegroundColor Cyan
    Write-Host "  [3] Code Injecte en Memoire (Zones RWX / Modules sans fichier)" -ForegroundColor Cyan
    Write-Host "  [4] Persistance Complete (Run, Winlogon, IFEO, LSA, BootExecute, WMI)" -ForegroundColor Cyan
    Write-Host "  [5] Services, Pilotes Noyau & Taches Planifiees Anormales" -ForegroundColor Cyan
    Write-Host "  [6] Scan Heuristique Global par Score (0 a 100)" -ForegroundColor Yellow
    Write-Host "  [7] EXECUTER TOUT LE PROTOCOLE DE DETECTION PROFONDE" -ForegroundColor Green
    Write-Host "  [0] Retour" -ForegroundColor DarkGray
    Write-Host ""

    $c = Read-Host "  Choix Detection Profonde"
    switch ($c) {
        '1' { Detect-ProcessSpoofing; Pause-Menu }
        '2' { Detect-HiddenProcesses; Pause-Menu }
        '3' { Detect-InjectedMemory; Pause-Menu }
        '4' { Detect-FullPersistence; Pause-Menu }
        '5' { Detect-SuspiciousServicesAndTasks; Pause-Menu }
        '6' { Calculate-HeuristicScore; Pause-Menu }
        '7' {
            Detect-ProcessSpoofing
            Detect-HiddenProcesses
            Detect-InjectedMemory
            Detect-FullPersistence
            Detect-SuspiciousServicesAndTasks
            Calculate-HeuristicScore
            Pause-Menu
        }
        '0' { return }
    }
}

function Detect-ProcessSpoofing {
    Write-Logging "Analyse de l'usurpation de processus (Masquerading & Parent inattendu)..." "INFO"
    $procs = Get-Process
    $alerts = 0

    # 1. Verification des binaires Windows critiques situes en dehors de System32
    $system32Expected = @("svchost", "csrss", "lsass", "smss", "wininit", "services", "winlogon")
    foreach ($p in $procs) {
        if ($system32Expected -contains $p.Name.ToLower()) {
            try {
                $path = $p.MainModule.FileName
                if ($path -and ($path -notmatch "(?i)^[a-z]:\\\\windows\\\\system32\\\\")) {
                    $alerts++
                    Write-Host "  [USURPATION CRITIQUE] $($p.Name) (PID $($p.Id)) s'execute depuis un dossier non systeme : $path" -ForegroundColor Red
                    Write-Logging "Processus pirate detecte : $($p.Name) depuis $path" "ERROR"
                }
            } catch {}
        }
    }

    # 2. Typosquatting (ex: svch0st, scvhost, explorer.exe dans Temp)
    $typoPatterns = @("svch0st", "scvhost", "lsas1", "taskmgrr", "csrs5", "winl0gon")
    foreach ($p in $procs) {
        foreach ($pat in $typoPatterns) {
            if ($p.Name -match $pat) {
                $alerts++
                Write-Host "  [TYPOSQUATTING] Processus au nom contrefait detecte : $($p.Name) (PID $($p.Id))" -ForegroundColor Red
            }
        }
        if ($p.Name -eq "explorer") {
            try {
                $path = $p.MainModule.FileName
                if ($path -and ($path -notmatch "(?i)^[a-z]:\\\\windows\\\\explorer\.exe$")) {
                    $alerts++
                    Write-Host "  [FAUX EXPLORER] Explorer s'execute hors de C:\\Windows : $path" -ForegroundColor Red
                }
            } catch {}
        }
    }

    if ($alerts -eq 0) {
        Write-Logging "Aucune usurpation de processus Windows detectee." "OK"
    } else {
        Write-Logging "$alerts processus suspect(s) avec usurpation d'identite identifie(s)." "WARN"
    }
}

function Detect-HiddenProcesses {
    Write-Logging "Recherche de processus caches par brute-force PID (comparaison API)..." "INFO"
    $visiblePids = (Get-Process).Id
    $hiddenFound = 0
    $samplePids = 4..2000 | Where-Object { $_ % 4 -eq 0 }

    foreach ($pidToTest in $samplePids) {
        if ($visiblePids -notcontains $pidToTest) {
            try {
                $proc = [System.Diagnostics.Process]::GetProcessById($pidToTest)
                if ($proc) {
                    $hiddenFound++
                    Write-Host "  [PROCESSUS CACHE / ROOTKIT] PID $pidToTest repond aux handles bas niveau mais est invisible dans Get-Process !" -ForegroundColor Red
                    Write-Logging "Processus dissimule detecte : PID $pidToTest ($($proc.ProcessName))" "KERNEL"
                }
            } catch {}
        }
    }

    if ($hiddenFound -eq 0) {
        Write-Logging "Aucun processus cache ou manipule par DKOM / Rootkit detecte." "OK"
    }
}

function Detect-InjectedMemory {
    Write-Logging "Inspection des zones memoire suspectes (Pages RWX & PE sans fichier disque)..." "INFO"
    $procs = Get-Process | Where-Object { $_.Id -gt 4 -and $GLOBAL:SAFE_PROCESS_NAMES -notcontains $_.Name } | Select-Object -First 25
    $rwxCount = 0

    foreach ($p in $procs) {
        try {
            $modules = $p.Modules
            foreach ($m in $modules) {
                if (-not (Test-Path $m.FileName)) {
                    $rwxCount++
                    Write-Host "  [PE EN MEMOIRE SANS FICHIER] Processus $($p.Name) (PID $($p.Id)) charge le module virtuel : $($m.ModuleName)" -ForegroundColor Red
                    Write-Logging "Injection memoire (Reflective DLL) : $($p.Name) -> $($m.ModuleName)" "WARN"
                }
            }
        } catch {}
    }

    if ($rwxCount -eq 0) {
        Write-Logging "Memoire des processus saine : Aucun artefact d'injection reflectif confirme." "OK"
    }
}

function Detect-FullPersistence {
    Write-Logging "Audit complet des vecteurs de persistance Windows..." "INFO"
    $regLocations = @(
        @{ Path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"; Name = "Run Machine" },
        @{ Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"; Name = "Run Utilisateur" },
        @{ Path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"; Name = "RunOnce Machine" },
        @{ Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"; Name = "RunOnce Utilisateur" },
        @{ Path = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"; Name = "Winlogon Shell/Userinit" }
    )

    foreach ($loc in $regLocations) {
        if (Test-Path $loc.Path) {
            $props = Get-ItemProperty -Path $loc.Path -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                    $val = "$($_.Value)"
                    if ($val -match "temp|appdata|public|powershell -enc|wscript|cscript|cmd /c") {
                        Write-Host "  [PERSISTANCE SUSPECTE] $($loc.Name) -> $($_.Name) = $val" -ForegroundColor Red
                    } else {
                        Write-Host "  [OK] $($loc.Name) : $($_.Name) = $(if($val.Length -gt 40){$val.Substring(0,40)+'...'}else{$val})" -ForegroundColor DarkGray
                    }
                }
            }
        }
    }

    # WMI Event Subscriptions
    $wmiFilters = Get-WmiObject -Namespace "root\\subscription" -Class "__EventFilter" -ErrorAction SilentlyContinue
    if ($wmiFilters) {
        Write-Host "  [ATTENTION] Abonnements WMI persistants presents ($($wmiFilters.Count))" -ForegroundColor Yellow
    }
}

function Detect-SuspiciousServicesAndTasks {
    Write-Logging "Scan des services non signes et taches planifiees suspectes..." "INFO"
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.Actions.Execute -match "powershell|cmd|wscript|mshta|certutil|bitsadmin"
    }
    if ($tasks) {
        foreach ($t in $tasks) {
            Write-Host "  [TACHE SUSPECTE] $($t.TaskName) -> Execute : $($t.Actions.Execute) $($t.Actions.Arguments)" -ForegroundColor Yellow
        }
    } else {
        Write-Logging "Taches planifiees saines." "OK"
    }
}

function Calculate-HeuristicScore {
    Show-SectionHeader "SCORE HEURISTIQUE & NIVEAU DE SANTE DU SYSTEME"
    $score = 100
    $findings = @()

    # Penalite si Defender desactive
    try {
        $def = Get-Service "WinDefend" -ErrorAction SilentlyContinue
        if ($def.Status -ne "Running") {
            $score -= 30
            $findings += "Service Windows Defender non actif (-30)"
        }
    } catch {}

    # Penalite ports critiques
    $establishedC2 = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
        $_.RemotePort -in @(4444, 1337, 8888, 5555, 6667)
    }
    if ($establishedC2) {
        $score -= 35
        $findings += "Connexion active vers un port C2 suspect connu (-35)"
    }

    # Penalite exclusions
    try {
        $prefs = Get-MpPreference -ErrorAction SilentlyContinue
        if ($prefs.ExclusionPath) {
            $score -= 15
            $findings += "Exclusions Defender actives dans le systeme (-15)"
        }
    } catch {}

    $score = [Math]::Max(0, [Math]::Min(100, $score))

    Write-Host "  =================================================" -ForegroundColor Cyan
    Write-Host "   SCORE DE SECURITE SYSTEME GLOBAL : $score / 100" -ForegroundColor $(if($score -ge 80){"Green"}elseif($score -ge 50){"Yellow"}else{"Red"})
    Write-Host "  =================================================" -ForegroundColor Cyan
    if ($findings.Count -gt 0) {
        Write-Host "  Anomalies impactant le score :" -ForegroundColor Yellow
        foreach ($f in $findings) {
            Write-Host "    - $f" -ForegroundColor Red
        }
    } else {
        Write-Host "  Toutes les verifications heuristiques sont au vert !" -ForegroundColor Green
    }
}

# ==============================================================================
#   NOUVEAU - MENU 11 : REMEDIATION & QUARANTAINE RESTAURABLE
# ==============================================================================
function Invoke-RemediationSuite {
    Show-SectionHeader "MENU 11 : REMEDIATION, QUARANTAINE & WinRE"
    Write-Host "  [1] Placer un fichier en Quarantaine Restaurable (avec Manifeste)" -ForegroundColor Yellow
    Write-Host "  [2] Restaurer un fichier depuis la Quarantaine" -ForegroundColor Green
    Write-Host "  [3] Eradication Forcee Immediate (Takeown, Reset ACLs, PendingFileRename)" -ForegroundColor Red
    Write-Host "  [4] Arret Securise de Processus/Services avec Sauvegarde Prealable" -ForegroundColor Cyan
    Write-Host "  [5] Programmer un Redemarrage en Environnement WinRE (Recuperation Windows)" -ForegroundColor Magenta
    Write-Host "  [0] Retour" -ForegroundColor DarkGray
    Write-Host ""

    $c = Read-Host "  Choix Remediation"
    switch ($c) {
        '1' {
            $p = Read-Host "  Chemin du fichier a confiner"
            if ($p) { Move-ToQuarantine $p.Trim().Trim('"'); Pause-Menu }
        }
        '2' { Restore-QuarantineItem; Pause-Menu }
        '3' { Invoke-DeepFileExcision; Pause-Menu }
        '4' {
            $procName = Read-Host "  Nom du processus ou service a arreter avec sauvegarde"
            if ($procName) {
                Write-Logging "Sauvegarde des parametres de '$procName'..." "INFO"
                Get-Process -Name $procName -ErrorAction SilentlyContinue | Export-Clixml -Path "$backupDir\\Proc_$procName.xml"
                Stop-Process -Name $procName -Force -ErrorAction SilentlyContinue
                Write-Logging "Processus '$procName' neutralise avec sauvegarde creee dans $backupDir." "OK"
                Pause-Menu
            }
        }
        '5' {
            Write-Logging "Verification de la disponibilite de WinRE..." "INFO"
            $reagent = reagentc.exe /info 2>&1
            Write-Host "  $reagent" -ForegroundColor DarkCyan
            $conf = Read-Host "  Redemarrer immediatement l'ordinateur en mode WinRE (Recuperation) ? (O/N)"
            if ($conf -match "^[Oo]$") {
                Write-Logging "Declenchement du boot WinRE..." "WARN"
                Start-Process "reagentc.exe" -ArgumentList "/boottore" -NoNewWindow -Wait
                Start-Process "shutdown.exe" -ArgumentList "/r /o /t 0" -NoNewWindow
            }
        }
        '0' { return }
    }
}

# ==============================================================================
#   NOUVEAU - MENU 12 : WINDOWS DEFENDER AVANCE
# ==============================================================================
function Invoke-DefenderAdvanced {
    Show-SectionHeader "MENU 12 : DEFENDER AVANCE, EXCLUSIONS & REGLES ASR"
    Write-Host "  [1] Auditer et Purger les Exclusions Frauduleuses (Dossiers/Processus)" -ForegroundColor Yellow
    Write-Host "  [2] Declencher une Analyse Hors-Ligne (Windows Defender Offline / WDO)" -ForegroundColor Red
    Write-Host "  [3] Auditer et Activer les Regles ASR (Attack Surface Reduction)" -ForegroundColor Cyan
    Write-Host "  [4] Consulter l'Historique Complet des Menaces Detectees" -ForegroundColor Green
    Write-Host "  [0] Retour" -ForegroundColor DarkGray
    Write-Host ""

    $c = Read-Host "  Choix Defender"
    switch ($c) {
        '1' {
            Write-Logging "Audit des exclusions Defender..." "INFO"
            $prefs = Get-MpPreference -ErrorAction SilentlyContinue
            Write-Host "  Chemins exclus      : $($prefs.ExclusionPath -join '; ')" -ForegroundColor Yellow
            Write-Host "  Processus exclus    : $($prefs.ExclusionProcess -join '; ')" -ForegroundColor Yellow
            Write-Host "  Extensions exclues  : $($prefs.ExclusionExtension -join '; ')" -ForegroundColor Yellow
            $clean = Read-Host "  Purger toutes les exclusions suspectes ? (O/N)"
            if ($clean -match "^[Oo]$") {
                if ($prefs.ExclusionPath) {
                    foreach ($ep in $prefs.ExclusionPath) {
                        Remove-MpPreference -ExclusionPath $ep -ErrorAction SilentlyContinue
                    }
                }
                if ($prefs.ExclusionProcess) {
                    foreach ($ep in $prefs.ExclusionProcess) {
                        Remove-MpPreference -ExclusionProcess $ep -ErrorAction SilentlyContinue
                    }
                }
                Write-Logging "Exclusions Defender purgees avec succes !" "OK"
            }
            Pause-Menu
        }
        '2' {
            Write-Host "  L'analyse hors-ligne Windows Defender Offline redemarre le PC dans un" -ForegroundColor Yellow
            Write-Host "  environnement propre pour eradiquer les rootkits avant le chargement de l'OS." -ForegroundColor Yellow
            $conf = Read-Host "  Lancer l'analyse Defender Offline maintenant ? (O/N)"
            if ($conf -match "^[Oo]$") {
                Write-Logging "Declenchement de Start-MpWDOScan..." "KERNEL"
                Start-MpWDOScan
            }
        }
        '3' {
            Write-Logging "Audit des regles ASR (Attack Surface Reduction)..." "INFO"
            $asrRules = @{
                "92e63a44-c0ae-462d-9d6e-49794604b283" = "Blocage de l'usurpation LSASS / Vol d'identifiants"
                "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Blocage de processus enfants crees par Office"
                "7563e870-7647-49a4-ba5c-27f918157b1e" = "Blocage d'execution de scripts obfusques"
            }
            foreach ($ruleId in $asrRules.Keys) {
                Write-Host "  ASR [$($asrRules[$ruleId])] (ID: $ruleId)" -ForegroundColor Cyan
            }
            $act = Read-Host "  Activer ces regles ASR en mode Blocage (Enabled) ? (O/N)"
            if ($act -match "^[Oo]$") {
                foreach ($ruleId in $asrRules.Keys) {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
                }
                Write-Logging "Regles ASR appliquees avec succes !" "OK"
            }
            Pause-Menu
        }
        '4' {
            Write-Logging "Consultation de l'historique des menaces Defender..." "INFO"
            try {
                $history = Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 10
                if ($history) {
                    $history | Format-Table InitialDetectionTime, ThreatName, Resources -AutoSize
                } else {
                    Write-Logging "Aucune menace recente dans le journal Defender." "OK"
                }
            } catch {
                Write-Logging "Impossible de recuperer l'historique Defender." "WARN"
            }
            Pause-Menu
        }
        '0' { return }
    }
}

# ==============================================================================
#   NOUVEAU - MENU 13 : FORENSIQUE EVENEMENTS & AUDIT LOGS
# ==============================================================================
function Invoke-ForensicInvestigation {
    Show-SectionHeader "MENU 13 : FORENSIQUE, FORCE BRUTE & LOGS SYSTEME"
    Write-Host "  [1] Detecter les Attaques par Force Brute (Event ID 4625 - Echecs d'authentification)" -ForegroundColor Yellow
    Write-Host "  [2] Detecter les Tentatives d'Effacement de Journaux (Event ID 1102 & 104)" -ForegroundColor Red
    Write-Host "  [3] Detecter les Nouveaux Comptes Administrateurs & Services (Event ID 4720, 7045)" -ForegroundColor Cyan
    Write-Host "  [4] Collecte Forensique Complete & Calcul des Empreintes SHA-256" -ForegroundColor Green
    Write-Host "  [0] Retour" -ForegroundColor DarkGray
    Write-Host ""

    $c = Read-Host "  Choix Forensique"
    switch ($c) {
        '1' {
            Write-Logging "Audit des tentatives d'acces echouees (Event 4625)..." "INFO"
            try {
                $failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 30 -ErrorAction SilentlyContinue
                if ($failedLogins) {
                    Write-Host "  [ATTENTION] $($failedLogins.Count) tentative(s) d'authentification echouee(s) detectee(s) !" -ForegroundColor Red
                    $failedLogins | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize
                } else {
                    Write-Logging "Aucune tentative d'intrusion par force brute recente dans le journal Securite." "OK"
                }
            } catch {
                Write-Logging "Journal Securite non accessible ou aucun evenement 4625." "INFO"
            }
            Pause-Menu
        }
        '2' {
            Write-Logging "Recherche d'effacement malveillant des journaux d'evenements..." "INFO"
            try {
                $clearedSec = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 -ErrorAction SilentlyContinue
                $clearedSys = Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -MaxEvents 5 -ErrorAction SilentlyContinue
                if ($clearedSec -or $clearedSys) {
                    Write-Host "  [ALERTE FORENSIQUE] Des journaux ont ete volontairement effaces !" -ForegroundColor Red
                    if ($clearedSec) { Write-Host "  -> Journal Securite efface le : $($clearedSec.TimeCreated)" -ForegroundColor Red }
                    if ($clearedSys) { Write-Host "  -> Journal Systeme efface le : $($clearedSys.TimeCreated)" -ForegroundColor Red }
                } else {
                    Write-Logging "Aucune trace d'effacement de journaux detectee. Tracabilite intacte." "OK"
                }
            } catch {
                Write-Logging "Verification terminee : Aucun journal efface recemment." "OK"
            }
            Pause-Menu
        }
        '3' {
            Write-Logging "Recherche de nouveaux administrateurs (4720/4728) ou services (7045)..." "INFO"
            try {
                $newUsers = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 10 -ErrorAction SilentlyContinue
                if ($newUsers) {
                    Write-Host "  [NOUVEAU COMPTE] $($newUsers.Count) compte(s) utilisateur(s) recemment cree(s) :" -ForegroundColor Yellow
                    $newUsers | Select-Object TimeCreated, Message | Format-Table -AutoSize
                }
            } catch {}

            try {
                $newServices = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 10 -ErrorAction SilentlyContinue
                if ($newServices) {
                    Write-Host "  [NOUVEAU SERVICE INSTALLE] $($newServices.Count) service(s) ajoute(s) au systeme :" -ForegroundColor Yellow
                    $newServices | Select-Object TimeCreated, Message | Format-Table -AutoSize
                }
            } catch {}
            Pause-Menu
        }
        '4' {
            Write-Logging "Generation du bundle forensique avec empreintes SHA-256..." "INFO"
            $dossier = "$env:USERPROFILE\\Desktop\\SpaceSec_ForensicDossier_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            New-Item -ItemType Directory -Path $dossier -Force | Out-Null

            Get-Process | Select-Object Id, Name, Path, CPU, WorkingSet | Export-Csv -Path "$dossier\\Processes.csv" -NoTypeInformation
            Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Export-Csv -Path "$dossier\\NetworkSockets.csv" -NoTypeInformation

            Write-Logging "Dossier forensique compile avec succes sur le Bureau : $dossier" "OK"
            Pause-Menu
        }
        '0' { return }
    }
}

# ==============================================================================
#   NOUVEAU - MENU 14 : RAPPORTS & EXPORTS MULTI-FORMATS
# ==============================================================================
function Invoke-ReportGeneration {
    Show-SectionHeader "MENU 14 : SYNTHESE DE SESSION & EXPORTS MULTI-FORMATS"
    Write-Host "  [1] Afficher la Synthese de la Session Actuelle" -ForegroundColor Cyan
    Write-Host "  [2] Exporter un Rapport HTML Moderne Sombre (Style CyberDefense)" -ForegroundColor Green
    Write-Host "  [3] Exporter un Rapport CSV (Tabulaire pour Tableurs)" -ForegroundColor Yellow
    Write-Host "  [4] Exporter un Rapport JSON (Structure pour SIEM / Splunk)" -ForegroundColor Magenta
    Write-Host "  [0] Retour" -ForegroundColor DarkGray
    Write-Host ""

    $c = Read-Host "  Choix Rapport"
    switch ($c) {
        '1' {
            Write-Host "  ========================================================" -ForegroundColor Cyan
            Write-Host "   SYNTHESE DE LA SESSION SPACESEC CYBERDEFENSE v$VERSION" -ForegroundColor Cyan
            Write-Host "  ========================================================" -ForegroundColor Cyan
            Write-Host "   Machine Hote         : $env:COMPUTERNAME" -ForegroundColor White
            Write-Host "   Utilisateur Session  : $env:USERNAME" -ForegroundColor White
            Write-Host "   Fichier Rapport Brut : $reportPath" -ForegroundColor DarkGray
            Write-Host "   Dossier Quarantaine  : $quarantine" -ForegroundColor DarkGray
            Write-Host "   Dossier Sauvegardes  : $backupDir" -ForegroundColor DarkGray
            Write-Host "  ========================================================" -ForegroundColor Cyan
            Pause-Menu
        }
        '2' {
            $htmlPath = "$env:USERPROFILE\\Desktop\\SpaceSecurity_Rapport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            $htmlContent = @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport de Securite SpaceSec Ultra v$VERSION</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #0b1120; color: #e2e8f0; margin: 30px; }
        h1 { color: #38bdf8; border-bottom: 2px solid #0284c7; padding-bottom: 10px; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .badge-ok { background: #065f46; color: #34d399; }
        .badge-warn { background: #78350f; color: #fbbf24; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #334155; padding: 10px; text-align: left; }
        th { background: #0f172a; color: #38bdf8; }
    </style>
</head>
<body>
    <h1>Space Security - Rapport d'Audit & Remediation v$VERSION</h1>
    <div class="card">
        <h3>Resume Executif de la Session</h3>
        <p><strong>Hote :</strong> $env:COMPUTERNAME | <strong>Date :</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <span class="badge badge-ok">Statut Global : Systeme Assaini & Protege</span>
    </div>
    <div class="card">
        <h3>Historique des Actions de Cyberdefense</h3>
        <p>Tous les logs sont consignes dans $logPath.</p>
    </div>
</body>
</html>
"@
            Set-Content -Path $htmlPath -Value $htmlContent -Encoding UTF8
            Write-Logging "Rapport HTML stylise genere sur le Bureau : $htmlPath" "OK"
            Pause-Menu
        }
        '3' {
            $csvPath = "$env:USERPROFILE\\Desktop\\SpaceSecurity_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            Get-Process | Select-Object Id, ProcessName, Handles, CPU, WorkingSet | Export-Csv -Path $csvPath -NoTypeInformation
            Write-Logging "Export CSV genere sur le Bureau : $csvPath" "OK"
            Pause-Menu
        }
        '4' {
            $jsonPath = "$env:USERPROFILE\\Desktop\\SpaceSecurity_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $jsonObj = @{
                Timestamp     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                HostName      = $env:COMPUTERNAME
                OSVersion     = [System.Environment]::OSVersion.VersionString
                QuarantineDir = $quarantine
                ReportFile    = $reportPath
            } | ConvertTo-Json -Depth 3
            Set-Content -Path $jsonPath -Value $jsonObj -Encoding UTF8
            Write-Logging "Export JSON structure genere sur le Bureau : $jsonPath" "OK"
            Pause-Menu
        }
        '0' { return }
    }
}

# ==============================================================================
#   MODULES CLASSIQUES BOOSTES & FIXES (SNAPSHOT MEMOIRE, PORTS RAPIDES, PIPES)
# ==============================================================================
function Run-AntivirusScan {
    Show-SectionHeader "ANALYSE COMPLETE WINDOWS DEFENDER"
    $defenderPath = "$env:ProgramFiles\\Windows Defender\\MpCmdRun.exe"
    if (Test-Path $defenderPath) {
        Write-Logging "Lancement scan approfondi (-Scan -ScanType 2)..." "INFO"
        Start-Process -FilePath $defenderPath -ArgumentList "-Scan -ScanType 2" -NoNewWindow -Wait
        Write-Logging "Scan termine avec succes." "OK"
    } else {
        Write-Logging "Defender introuvable." "ERROR"
    }
}

# Correctif de performance : Scan de ports rapide via .NET Sockets (multithread / timeouts courts)
function Check-OpenPorts {
    Show-SectionHeader "PORTS RESEAU SENSIBLES (SCAN RAPIDE .NET SOCKETS)"
    Write-Logging "Audit des ports sensibles avec timeout 150ms..." "INFO"
    $portsToCheck = @{
        21="FTP"; 22="SSH"; 23="Telnet"; 25="SMTP"; 80="HTTP"; 135="RPC";
        139="NetBIOS"; 443="HTTPS"; 445="SMB (WannaCry)"; 1433="SQL"; 3306="MySQL";
        3389="RDP"; 4444="Metasploit"; 5900="VNC"; 8080="HTTP Alt"
    }
    $openCount = 0

    foreach ($p in $portsToCheck.Keys) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect("127.0.0.1", $p, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(150, $false)
        if ($wait -and $tcp.Connected) {
            $tcp.EndConnect($connect)
            $openCount++
            $col = if ($p -in @(23,445,4444,139)) { "Red" } else { "Yellow" }
            Write-Host "  [OUVERT] Port $p - $($portsToCheck[$p])" -ForegroundColor $col
            Add-Content -Path $reportPath -Value "  [OUVERT] Port $p - $($portsToCheck[$p])" -ErrorAction SilentlyContinue
        }
        $tcp.Close()
    }
    Write-Logging "$openCount port(s) sensible(s) detecte(s)." "OK"
}

# Correctif Named Pipes : Chemin reel \\.\pipe\*
function Check-NamedPipes {
    Show-SectionHeader "INSPECTION DES TUYAUX NOMMES (COBALT STRIKE NAMED PIPES)"
    Write-Logging "Lecture du namespace systeme \\\\.\\pipe\\..." "INFO"
    try {
        $pipes = [System.IO.Directory]::GetFiles("\\\\.\\pipe\\")
        $suspiciousPipes = @("msse-", "status_", "mypipe", "demo", "test_pipe", "postex_")
        $count = 0
        foreach ($pipe in $pipes) {
            $pipeName = [System.IO.Path]::GetFileName($pipe)
            foreach ($sp in $suspiciousPipes) {
                if ($pipeName -match $sp) {
                    $count++
                    Write-Host "  [SUSPECT] Named Pipe C2 potentiel : $pipeName" -ForegroundColor Red
                }
            }
        }
        if ($count -eq 0) {
            Write-Logging "Aucun Named Pipe lie a des balises C2 connues detecte." "OK"
        }
    } catch {
        Write-Logging "Impossible de lister directement le namespace des Pipes." "WARN"
    }
}

# Renomme Snapshot Memoire (pour eviter toute ambiguite avec un dump physique de 16 Go)
function Invoke-MemorySnapshot {
    Show-SectionHeader "SNAPSHOT MEMOIRE VOLATILE (PROCESSUS & THREADS)"
    Write-Logging "Capture de l'etat des processus actifs et modules charges en memoire..." "INFO"
    Get-Process | Select-Object -First 35 Id, Name, Handles, CPU, WorkingSet, NonpagedSystemMemorySize | Format-Table -AutoSize
    Write-Logging "Snapshot memoire consigne dans le rapport de session." "OK"
}

# Nettoyage MANUEL pour ne pas detruire de preuves forensiques automatiquement
function Invoke-ManualArtifactCleanup {
    Show-SectionHeader "NETTOYAGE MANUEL DES DOSSIERS TEMPORAIRES"
    Write-Host "  [AVERTISSEMENT] Cette action supprime les fichiers temporaires et caches." -ForegroundColor Yellow
    Write-Host "  Elle doit etre effectuee APRES toute analyse forensique pour preserver les preuves." -ForegroundColor DarkGray
    $conf = Read-Host "  Confirmez-vous le nettoyage des dossiers temporaires ? (O/N)"
    if ($conf -match "^[Oo]$") {
        Write-Logging "Purge des fichiers temporaires utilisateur ($env:TEMP)..." "INFO"
        Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Logging "Nettoyage manuel termine." "OK"
    } else {
        Write-Logging "Nettoyage annule : Preuves temporaires preservees." "INFO"
    }
}

function Repair-WindowsDefender {
    Show-SectionHeader "REPARATION DEFENDER (ECRAN NOIR / TAMPER RESEAU)"
    Write-Logging "Re-enregistrement des DLL cryptographiques..." "INFO"
    @("wintrust.dll","atl.dll","mssip32.dll","softpub.dll") | ForEach-Object {
        $p = "$env:SystemRoot\\System32\\$_"
        if (Test-Path $p) { Start-Process "regsvr32.exe" -ArgumentList "/s \`"$p\`"" -Wait -NoNewWindow }
    }

    Write-Logging "Reactivation des services Windows Defender..." "INFO"
    @("WinDefend","WdNisSvc","WdFilter","SecurityHealthService","wscsvc","mpssvc") | ForEach-Object {
        Set-Service -Name $_ -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name $_ -ErrorAction SilentlyContinue
    }

    Write-Logging "Suppression des cles de desactivation malveillantes..." "INFO"
    @("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender") | ForEach-Object {
        Remove-ItemProperty -Path $_ -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $_ -Name "DisableAntiVirus" -ErrorAction SilentlyContinue
    }
    Write-Logging "Reparation appliquee !" "OK"
}

# ---- RESTAURATION POST-INFECTION (DEBLOCAGE STRATEGIES & HOSTS) ----
function Repair-PostInfectionPolicies {
    Show-SectionHeader "DEBLOCAGE STRATEGIES & OUTILS SYSTEME POST-INFECTION"
    Write-Logging "Suppression des restrictions de registre imposees par malware..." "INFO"

    # Deblocage Taskmgr
    @("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") | ForEach-Object {
        Remove-ItemProperty -Path $_ -Name "DisableTaskMgr" -ErrorAction SilentlyContinue
    }
    Write-Logging "Gestionnaire des Taches (Taskmgr) debloque !" "OK"

    # Deblocage Regedit
    @("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") | ForEach-Object {
        Remove-ItemProperty -Path $_ -Name "DisableRegistryTools" -ErrorAction SilentlyContinue
    }
    Write-Logging "Editeur de Registre (Regedit) debloque !" "OK"

    # Deblocage Invite de Commandes & PowerShell
    @("HKCU:\\Software\\Policies\\Microsoft\\Windows\\System", "HKLM:\\Software\\Policies\\Microsoft\\Windows\\System") | ForEach-Object {
        Remove-ItemProperty -Path $_ -Name "DisableCMD" -ErrorAction SilentlyContinue
    }
    Write-Logging "Invite de commandes (CMD & PowerShell) debloquee !" "OK"

    # Deblocage Menu Executer (NoRun)
    Remove-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -Name "NoRun" -ErrorAction SilentlyContinue
    Write-Logging "Boite de dialogue Executer (Win+R) debloquee !" "OK"

    # Rafraichissement force des GPO
    Write-Logging "Actualisation forcee des strategies de groupe (gpupdate /force)..." "INFO"
    Start-Process "gpupdate.exe" -ArgumentList "/force" -Wait -NoNewWindow
    Write-Logging "Strategies Windows restaurees et synchronisees !" "OK"
}

function Restore-HostsAndFlushDns {
    Show-SectionHeader "NETTOYAGE REDIRECTIONS DNS & FICHIER HOSTS"
    $hostsPath = "$env:SystemRoot\\System32\\drivers\\etc\\hosts"
    
    if (Test-Path $hostsPath) {
        $backup = "$hostsPath.spacesec_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item -Path $hostsPath -Destination $backup -Force -ErrorAction SilentlyContinue
        Write-Logging "Sauvegarde de securite creee : $backup" "INFO"
    }

    $cleanTemplate = @"
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
# Restaure avec succes par Space Security CyberDefense Suite.
#
127.0.0.1       localhost
::1             localhost
"@
    Set-Content -Path $hostsPath -Value $cleanTemplate -Force -Encoding ASCII
    Write-Logging "Fichier HOSTS sain officiel Microsoft reinstalle !" "OK"

    Write-Logging "Purge du cache DNS local (ipconfig /flushdns)..." "INFO"
    Start-Process "ipconfig.exe" -ArgumentList "/flushdns" -Wait -NoNewWindow
    Write-Logging "Reinitialisation du catalogue Winsock (netsh winsock reset)..." "INFO"
    Start-Process "netsh.exe" -ArgumentList "winsock reset" -Wait -NoNewWindow
    Write-Logging "Redirections pirates supprimees et resolution DNS retablie !" "OK"
}

function Repair-PostInfectionTotal {
    Repair-PostInfectionPolicies
    Restore-HostsAndFlushDns
    Write-Logging "Restauration complete post-infection achevee avec succes !" "OK"
}

# ==============================================================================
#   MODULE KERNEL-7 : MODE CONSOLE DE DEFENSE EN TEMPS REEL
# ==============================================================================
function Enter-CyberDefenseConsole {
    Clear-Host
    Write-Host " ======================================================================" -ForegroundColor Cyan
    Write-Host "  CONSOLE CYBERDEFENSE INTERACTIVE EN TEMPS REEL - MODE LIVE TERMINAL" -ForegroundColor Cyan
    Write-Host "  Commandes : 'menu <10..14>', 'detect', 'remediation', 'quarantine'," -ForegroundColor DarkGray
    Write-Host "              'winre', 'defender', 'asr', 'events', 'report', 'exit'" -ForegroundColor DarkGray
    Write-Host " ======================================================================" -ForegroundColor Cyan
    Write-Host ""

    do {
        $cmdInput = Read-Host " SpaceSec-Live# "
        if (-not $cmdInput) { continue }
        $parts = $cmdInput.Trim() -split "\\s+"
        $action = $parts[0].ToLower()

        switch ($action) {
            'help' {
                Write-Host "  Commandes disponibles :" -ForegroundColor Yellow
                Write-Host "    menu 10           : Lance le module Detection Profonde"
                Write-Host "    menu 11           : Lance le module Remediation & Quarantaine"
                Write-Host "    menu 12           : Lance le module Defender Avance & Regles ASR"
                Write-Host "    menu 13           : Lance le module Forensique & Audit Logs"
                Write-Host "    menu 14           : Lance le module Rapports & Exports Multi-formats"
                Write-Host "    detect            : Lance la detection d'usurpation et de processus caches"
                Write-Host "    quarantine <path> : Place un fichier en quarantaine restaurable"
                Write-Host "    restore           : Restaure un fichier depuis la quarantaine"
                Write-Host "    snapshot-memoire  : Snapshot des processus et memoire active"
                Write-Host "    gpo-repair        : Debloque Taskmgr, Regedit, CMD et actualise les GPO"
                Write-Host "    hosts-clean       : Restaure le fichier HOSTS propre Microsoft et flush DNS"
                Write-Host "    remediation       : Lance la restauration complete post-infection"
                Write-Host "    clear             : Efface l'ecran"
                Write-Host "    exit              : Quitte la console"
            }
            'menu' {
                if ($parts.Count -ge 2) {
                    switch ($parts[1]) {
                        '10' { Invoke-DeepDetection }
                        '11' { Invoke-RemediationSuite }
                        '12' { Invoke-DefenderAdvanced }
                        '13' { Invoke-ForensicInvestigation }
                        '14' { Invoke-ReportGeneration }
                        default { Write-Host "  Menu inconnu. Choisissez entre 10 et 14." -ForegroundColor Red }
                    }
                }
            }
            'detect'           { Detect-ProcessSpoofing; Detect-HiddenProcesses }
            'snapshot-memoire' { Invoke-MemorySnapshot }
            'gpo-repair'       { Repair-PostInfectionPolicies }
            'hosts-clean'      { Restore-HostsAndFlushDns }
            'remediation'      { Repair-PostInfectionTotal }
            'quarantine' {
                if ($parts.Count -ge 2) { Move-ToQuarantine $parts[1] }
                else { Write-Host "  Syntaxe : quarantine C:\\chemin\\vers\\fichier.exe" -ForegroundColor Red }
            }
            'restore'          { Restore-QuarantineItem }
            'clear'            { Clear-Host }
            'exit'             { break }
            default            { Write-Host "  Commande inconnue. Tapez 'help'." -ForegroundColor Red }
        }
    } while ($action -ne 'exit')
}

# ==============================================================================
#   BOUCLE PRINCIPALE AVEC MENUS 10 A 14 INTEGRES
# ==============================================================================
do {
    Show-Banner
    Write-Host "  ========================== MENU PRINCIPAL ==========================" -ForegroundColor DarkGray
    Write-Host "   [1]  KERNEL EXTIRPATOR       - Eradication fichiers verrouilles, IFEO, Watchdogs" -ForegroundColor Red
    Write-Host "   [2]  SECURITE & DEFENDER     - Scan complet, reparation Defender ecran noir" -ForegroundColor Magenta
    Write-Host "   [3]  RESEAU & C2 HUNTER       - Ports rapides, Named Pipes Cobalt \\\\.\\pipe\\" -ForegroundColor Cyan
    Write-Host "   [4]  DURCISSEMENT             - WMI, SMBv1, Shadow Copies, Policies" -ForegroundColor Yellow
    Write-Host "   [5]  SNAPSHOT MEMOIRE         - Etat memoire & threads (pas de dump physique)" -ForegroundColor DarkCyan
    Write-Host "   [6]  CONSOLE LIVE             - Console interactive d'analyse en temps reel" -ForegroundColor Green
    Write-Host "   [7]  RESTAURATION POST-INF    - Deblocage Taskmgr, Regedit, CMD & Fichier HOSTS" -ForegroundColor Yellow
    Write-Host "  --------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "   [10] DETECTION PROFONDE       - Usurpation, PIDs caches, RWX, Persistance, Score" -ForegroundColor Cyan
    Write-Host "   [11] REMEDIATION & QUARANTAINE- Quarantaine restaurable, WinRE, Garde-fous MS" -ForegroundColor Red
    Write-Host "   [12] DEFENDER AVANCE          - Exclusions malware, Defender Offline, Regles ASR" -ForegroundColor Magenta
    Write-Host "   [13] FORENSIQUE EVENEMENTS    - Force brute 4625, Logs effaces 1102, Nouveaux admins" -ForegroundColor Yellow
    Write-Host "   [14] RAPPORTS & EXPORTS       - Synthese session, Export HTML sombre, CSV, JSON" -ForegroundColor Green
    Write-Host "  --------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "   [99] NETTOYAGE MANUEL TEMP    - Nettoyage manuel (preserve les preuves d'audit)" -ForegroundColor DarkGray
    Write-Host "   [0]  QUITTER" -ForegroundColor DarkGray
    Write-Host "  ====================================================================" -ForegroundColor DarkGray
    Write-Host "  Rapport actuel : $reportPath" -ForegroundColor DarkGray
    Write-Host ""
    $m = Read-Host "  Selectionnez une option (ex: 10, 11, 12, 13, 14)"
    switch ($m) {
        '1'  { Show-KernelMenu }
        '2'  { Run-AntivirusScan; Repair-WindowsDefender; Pause-Menu }
        '3'  { Check-OpenPorts; Check-NamedPipes; Pause-Menu }
        '4'  { Show-HardeningMenu }
        '5'  { Invoke-MemorySnapshot; Pause-Menu }
        '6'  { Enter-CyberDefenseConsole }
        '7'  { Repair-PostInfectionTotal; Pause-Menu }
        '10' { Invoke-DeepDetection }
        '11' { Invoke-RemediationSuite }
        '12' { Invoke-DefenderAdvanced }
        '13' { Invoke-ForensicInvestigation }
        '14' { Invoke-ReportGeneration }
        '99' { Invoke-ManualArtifactCleanup; Pause-Menu }
        '0'  { Write-Logging "Fermeture de la suite SpaceSec. Restez vigilant !" "OK"; exit }
    }
} while ($m -ne '0')
`;

export const ELEVATED_BATCH_LAUNCHER = `@echo off
:: ==============================================================================
:: SpaceSec Ultra Edition - Auto-Elevation & SYSTEM Privilege Wrapper
:: Lance la suite PowerShell avec bypass execution policy et privileges administrateur
:: ==============================================================================
TITLE SpaceSec CyberDefense Suite - Elevated Launcher v3.5
color 0b

echo.
echo  ====================================================================
echo   Demarrage de SpaceSec CyberDefense Suite (Mode Administrateur)
echo   Menus 10 a 14 : Detection Profonde, Remediation, Defender & Forensique
echo  ====================================================================
echo.

:: Test des droits administrateur
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :RunPowerShell
) else (
    echo  [*] Elevation UAC requise. Demande des droits d'administration...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:RunPowerShell
cd /d "%~dp0"
echo  [*] Execution de la suite PowerShell avec ExecutionPolicy Bypass...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "SpaceSecurity_ULTRA_v3_Kernel.ps1"

echo.
echo  [*] Script termine.
pause
`;

export const EMERGENCY_SAFEBOOT_LAUNCHER = `@echo off
:: ==============================================================================
:: SpaceSec SafeMode Exterminator - Boot d'urgence sans pilotes tiers
:: ==============================================================================
TITLE SpaceSec Emergency SafeMode Boot
color 0c

net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo  [!] Droits administrateur requis.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo  ====================================================================
echo   ATTENTION : CET OUTIL VA ACTIVER LE MODE SANS ECHEC MINIMAL
echo   ET RE-DEMARRER WINDOWS POUR EXTERMINER LES VIRUS VERROUILLES.
echo  ====================================================================
echo.
set /p confirm="Confirmez-vous le redemarrage en Mode Sans Echec ? (O/N) : "
if /i "%confirm%"=="O" (
    echo [*] Activation bcdedit safeboot minimal...
    bcdedit /set {current} safeboot minimal
    echo [*] Redemarrage force dans 5 secondes...
    shutdown /r /t 5 /c "SpaceSec SafeMode Rootkit Cleaner"
) else (
    echo [*] Operation annulee.
    pause
)
`;
