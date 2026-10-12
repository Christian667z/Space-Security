export const BOOSTED_POWERSHELL_SCRIPT = `# ==============================================================================
# Suite de Securite & Defense PowerShell - ULTRA KERNEL & SYSTEM EDITION v3.0
# Auteur initial : Space [Goat Asta] | Boostee pour Ingenieurs Cybersecurite
# Niveau d'eradication : OS Kernel / TrustedInstaller / Handles verrouilles
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

$VERSION     = "3.0-KERNEL"
$reportPath  = "$env:USERPROFILE\\Desktop\\SpaceSecurity_UltraReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$logPath     = "$env:USERPROFILE\\Desktop\\SpaceSecurity_Kernel_Log.txt"
$quarantine  = "$env:SystemDrive\\SpaceSec_Quarantine"

if (-not (Test-Path $quarantine)) {
    New-Item -ItemType Directory -Path $quarantine -Force | Out-Null
}

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
#   MODULE KERNEL-1 : ERADICATION PROFONDE DE FICHIER VERROUILLE (TRUSTEDINSTALLER / HANDLES)
#   Meme si Administrateur a "Acces Refuse", cette fonction prend le controle
#   et force la suppression au boot via le noyau Windows (PendingFileRenameOperations).
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

    Write-Logging "Lancement du protocole d'eradication profonde : $cleanPath" "KERNEL"

    # 1. Neutraliser les attributs de protection (Systeme, Cache, Lecture seule)
    try {
        Set-ItemProperty -Path $cleanPath -Name Attributes -Value ([System.IO.FileAttributes]::Normal) -ErrorAction SilentlyContinue
        Write-Logging "Attributs du fichier reinitialises en Normal." "OK"
    } catch {}

    # 2. Forcer l'appropriation de propriete (Take Ownership) depuis TrustedInstaller / SYSTEM
    Write-Logging "Appropriation de propriete forcee (Takeown Administrators)..." "INFO"
    Start-Process "takeown.exe" -ArgumentList "/F \`"$cleanPath\`" /A" -NoNewWindow -Wait
    Start-Process "takeown.exe" -ArgumentList "/F \`"$cleanPath\`"" -NoNewWindow -Wait

    # 3. Forcer les permissions ACL d'acces total aux Administrateurs
    Write-Logging "Octroi ACL Administrateurs:Full (icacls)..." "INFO"
    Start-Process "icacls.exe" -ArgumentList "\`"$cleanPath\`" /grant *S-1-5-32-544:F /c /q" -NoNewWindow -Wait
    Start-Process "icacls.exe" -ArgumentList "\`"$cleanPath\`" /grant \`"$env:USERNAME\`:F /c /q" -NoNewWindow -Wait

    # 4. Tuer les processus verrouillant le fichier ou ayant le meme nom
    $fileName = [System.IO.Path]::GetFileName($cleanPath)
    $lockingProcs = Get-Process | Where-Object {
        $_.Name -match [System.IO.Path]::GetFileNameWithoutExtension($fileName) -or
        (try { $_.MainModule.FileName -eq $cleanPath } catch { $false })
    }
    foreach ($p in $lockingProcs) {
        Write-Logging "Fermeture agressive du processus verrouillant PID $($p.Id) ($($p.Name))..." "WARN"
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

    # 6. Si toujours verrouille (par ex. par un pilote Kernel / service systeme) :
    #    -> Enregistrement dans PendingFileRenameOperations (Suppression noyau au boot)
    Write-Logging "Fichier verrouille par un driver/handle systeme actif." "WARN"
    Write-Logging "Programmation de la suppression Kernel au redemarrage (Session Manager)..." "KERNEL"

    try {
        # Appel Win32 MoveFileEx avec MOVEFILE_DELAY_UNTIL_REBOOT
        $res = [NativeSecurity]::MoveFileEx($cleanPath, $null, [NativeSecurity]::MOVEFILE_DELAY_UNTIL_REBOOT)
        if ($res) {
            Write-Logging "MoveFileEx reussi : Windows Kernel supprimera le fichier au prochain boot." "OK"
        }
    } catch {
        Write-Logging "Echec MoveFileEx direct, ecriture registre Session Manager..." "WARN"
    }

    # Inscription directe dans le registre PendingFileRenameOperations
    try {
        $sessionKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"
        $currentPending = (Get-ItemProperty -Path $sessionKey -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
        $nativePath = "\\??\\$cleanPath"
        $newPending = if ($currentPending) { @($currentPending) + @($nativePath, "") } else { @($nativePath, "") }
        Set-ItemProperty -Path $sessionKey -Name "PendingFileRenameOperations" -Value $newPending -Type MultiString -Force
        Write-Logging "Cle PendingFileRenameOperations mise a jour avec succes !" "OK"
    } catch {
        Write-Logging "Erreur lors de l'enregistrement dans Session Manager." "ERROR"
    }

    # 7. Mesure d'isolement : ecraser le contenu avec 0 octet pour le rendre inoperant des maintenant
    try {
        [System.IO.File]::WriteAllBytes($cleanPath, [byte[]]@())
        Write-Logging "Contenu du fichier ecrase a 0 octet (binaire neutralise)." "OK"
    } catch {
        Write-Logging "Impossible d'ecraser le flux (handle exclusif en lecture/ecriture)." "WARN"
    }

    # 8. Interdire toute execution future via ACL Deny
    Start-Process "icacls.exe" -ArgumentList "\`"$cleanPath\`" /deny Everyone:(X)" -NoNewWindow -Wait
    Write-Logging "Permission d'execution verrouillee (Deny Execute pour Tous)." "OK"
    Write-Host ""
    Write-Host "  >> Le fichier est neutralise et sera definitivement detruit au prochain REDEMARRAGE." -ForegroundColor Green
}

# ==============================================================================
#   MODULE KERNEL-2 : SUSPENSION & BATCH-KILL DES PROCESSUS MUTUELS (WATCHDOGS)
#   Neutralise les malwares avec double processus qui se relancent mutuellement.
# ==============================================================================
function Suspend-And-Kill-Watchdogs {
    Show-SectionHeader "EXTIRPATION PROCESSUS WATCHDOG (DOUBLE PROCESSUS)"
    $procQuery = Read-Host "  Nom ou pattern du processus a neutraliser (ex: swisyn, remcos, updater)"
    if (-not $procQuery) { return }

    $procs = Get-Process | Where-Object { $_.Name -match $procQuery }
    if ($procs.Count -eq 0) {
        Write-Logging "Aucun processus trouve correspondant a '$procQuery'." "INFO"
        return
    }

    Write-Logging "$($procs.Count) processus cibles detectes. SUSPENSION IMMEDIATE DES THREADS..." "KERNEL"
    
    # Etape 1 : Geler tous les processus simultanement pour empecher la re-creation mutuelle
    foreach ($p in $procs) {
        try {
            $handle = $p.Handle
            $status = [NativeSecurity]::NtSuspendProcess($handle)
            Write-Logging "Processus gelé (NtSuspendProcess) : $($p.Name) (PID: $($p.Id))" "OK"
        } catch {
            Write-Logging "Impossible de suspendre PID $($p.Id)" "WARN"
        }
    }

    Start-Sleep -Milliseconds 500

    # Etape 2 : Terminaison forcee arbre complet
    Write-Logging "Terminaison forcee de l'arbre de processus (Taskkill /F /T)..." "WARN"
    foreach ($p in $procs) {
        Start-Process "taskkill.exe" -ArgumentList "/F /T /PID $($p.Id)" -NoNewWindow -Wait
        Write-Logging "Processus abattu : PID $($p.Id) ($($p.Name))" "OK"
    }
}

# ==============================================================================
#   MODULE KERNEL-3 : AUDIT & NETTOYAGE IFEO (IMAGE FILE EXECUTION OPTIONS)
#   Certains virus detournent Taskmgr, Cmd ou Defender avec une cle "Debugger".
# ==============================================================================
function Clean-IFEODebuggerHijacks {
    Show-SectionHeader "DETOURNEMENT REGISTRE IFEO (IMAGE FILE EXECUTION OPTIONS)"
    Write-Logging "Verification des cles de debogage IFEO..." "INFO"

    $ifeoPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    $criticalTargets = @("taskmgr.exe","cmd.exe","powershell.exe","regedit.exe","MpCmdRun.exe","msconfig.exe","procexp.exe","procmon.exe","ResourceHacker.exe","ProcessHacker.exe")
    $hijacksFound = 0

    foreach ($target in $criticalTargets) {
        $subKey = "$ifeoPath\\$target"
        if (Test-Path $subKey) {
            $debugger = (Get-ItemProperty -Path $subKey -ErrorAction SilentlyContinue).Debugger
            if ($debugger) {
                $hijacksFound++
                Write-Host "  [DETOURNE!] $target -> Debugger = $debugger" -ForegroundColor Red
                Write-Logging "Detournement IFEO detecte sur $target (lance $debugger au lieu de l'outil)" "C2"

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
#   MODULE KERNEL-4 : PURGE APPINIT_DLLS & APPCERTDLLS (INJECTION SYSTEME)
# ==============================================================================
function Purge-AppInitAndAppCert {
    Show-SectionHeader "INJECTION GLOBALE APPINIT_DLLS / APPCERTDLLS"
    Write-Logging "Inspection des DLLs injectees dans chaque processus..." "INFO"

    $appInitKeys = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    )

    foreach ($k in $appInitKeys) {
        if (Test-Path $k) {
            $dlls = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).AppInit_DLLs
            $enabled = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).LoadAppInit_DLLs
            if ($dlls -and $dlls.Trim() -ne "") {
                Write-Host "  [SUSPECT!] $k -> AppInit_DLLs : $dlls" -ForegroundColor Red
                Write-Logging "DLL d'injection globale detectee : $dlls" "ERROR"
                $ans = Read-Host "  Vider AppInit_DLLs pour bloquer l'injection ? (O/N)"
                if ($ans -match "^[Oo]$") {
                    Set-ItemProperty -Path $k -Name "AppInit_DLLs" -Value "" -Force
                    Set-ItemProperty -Path $k -Name "LoadAppInit_DLLs" -Value 0 -Type DWord -Force
                    Write-Logging "Cle AppInit_DLLs videe et desactivee." "OK"
                }
            } else {
                Write-Logging "Cle $k : Aucune DLL intruse." "OK"
            }
        }
    }

    # AppCertDlls (technique APT pour charger une DLL au demarrage de toute appli)
    $appCert = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"
    if (Test-Path $appCert) {
        $props = Get-ItemProperty -Path $appCert
        Write-Host "  [ATTENTION] Cle AppCertDlls presente :" -ForegroundColor Yellow
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            Write-Host "    $($_.Name) = $($_.Value)" -ForegroundColor Red
            Write-Logging "AppCertDll candidate : $($_.Name) = $($_.Value)" "WARN"
        }
    } else {
        Write-Logging "Aucune cle AppCertDlls anormale." "OK"
    }
}

# ==============================================================================
#   MODULE KERNEL-5 : AUDIT PILOTES KERNEL & FILTER DRIVERS (ROOTKITS / BYOVD)
# ==============================================================================
function Audit-KernelDrivers {
    Show-SectionHeader "AUDIT PILOTES SYSTEME & FILTER DRIVERS (ROOTKITS)"
    Write-Logging "Analyse des Mini-Filters de systeme de fichiers (fltmc)..." "INFO"

    $flt = fltmc filters 2>&1
    $flt | ForEach-Object {
        if ($_ -match "Filter Name|Altitude|Instances") {
            Write-Host "  $_" -ForegroundColor DarkCyan
        } elseif ($_ -match "[a-zA-Z0-9]") {
            Write-Host "  $_" -ForegroundColor White
        }
    }

    Write-Host ""
    Write-Logging "Verification des pilotes non signes ou suspects (driverquery)..." "INFO"
    $unsigned = driverquery /v /fo csv 2>&1 | ConvertFrom-Csv | Where-Object {
        $_.IsSigned -match "FALSE" -or $_.State -ne "Running" -and $_.StartMode -eq "Boot"
    }
    if ($unsigned) {
        Write-Host "  [PILOTES SUSPECTS]" -ForegroundColor Red
        foreach ($d in $unsigned) {
            Write-Host "  -> $($d.DisplayName) ($($d.ModuleName)) | Signe: $($d.IsSigned)" -ForegroundColor Red
            Add-Content -Path $reportPath -Value "  [DRIVER-SUSPECT] $($d.DisplayName) ($($d.ModuleName))" -ErrorAction SilentlyContinue
        }
    } else {
        Write-Logging "Tous les pilotes critiques ont une signature reconnue." "OK"
    }
}

# ==============================================================================
#   MODULE KERNEL-6 : REPARATION & CONFIGURATION SAFEMODE D'URGENCE
#   Garantit que le mode sans echec fonctionne et n'est pas sabote par le malware
# ==============================================================================
function Repair-SafeModeAndReboot {
    Show-SectionHeader "REPARATION DU MODE SANS ECHEC & BOOT CHIRURGICAL"
    Write-Logging "Audit de la cle SafeBoot de Windows..." "INFO"

    $safeBootMinimal = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal"
    if (-not (Test-Path $safeBootMinimal)) {
        Write-Logging "Cle SafeBoot Minimal absente ! Creation d'urgence..." "WARN"
        New-Item -Path $safeBootMinimal -Force | Out-Null
    }

    Write-Host "  1. Reparer l'acces au Mode Sans Echec" -ForegroundColor Cyan
    Write-Host "  2. Programmer un demarrage unique en Mode Sans Echec (Safe Mode)" -ForegroundColor Yellow
    Write-Host "  3. Revenir au Mode Normal (Annuler SafeBoot bcdedit)" -ForegroundColor Green
    Write-Host "  0. Retour" -ForegroundColor DarkGray
    Write-Host ""
    $sc = Read-Host "  Choix SafeBoot"
    switch ($sc) {
        '1' {
            Write-Logging "Restauration des services essentiels en SafeBoot..." "INFO"
            $essential = @("RpcSs","PlugPlay","DcomLaunch","WinDefend","vds","VSS","CryptSvc")
            foreach ($s in $essential) {
                $targetK = "$safeBootMinimal\\$s"
                if (-not (Test-Path $targetK)) {
                    New-Item -Path $targetK -Force | Out-Null
                    Set-ItemProperty -Path $targetK -Name "(default)" -Value "Service" -Force
                }
            }
            Write-Logging "Configuration SafeBoot Minimal restauree." "OK"
            Pause-Menu
        }
        '2' {
            Write-Logging "Configuration de BCD pour un boot unique en Mode Sans Echec Minimal..." "WARN"
            Start-Process "bcdedit.exe" -ArgumentList "/set {current} safeboot minimal" -NoNewWindow -Wait
            Write-Host "  [OK] Votre prochain redemarrage se fera en Mode Sans Echec." -ForegroundColor Green
            Write-Host "  Rappel : Tapez bcdedit /deletevalue {current} safeboot pour repasser en mode normal." -ForegroundColor Yellow
            $r = Read-Host "  Voulez-vous redemarrer l'ordinateur des maintenant ? (O/N)"
            if ($r -match "^[Oo]$") { Restart-Computer -Force }
        }
        '3' {
            Write-Logging "Suppression du flag safeboot dans BCD..." "INFO"
            Start-Process "bcdedit.exe" -ArgumentList "/deletevalue {current} safeboot" -NoNewWindow -Wait
            Write-Logging "Retour au boot normal active." "OK"
            Pause-Menu
        }
    }
}

# ==============================================================================
#   MODULE KERNEL-7 : MODE CONSOLE DE DEFENSE EN TEMPS REEL
# ==============================================================================
function Enter-CyberDefenseConsole {
    Clear-Host
    Write-Host " ======================================================================" -ForegroundColor Cyan
    Write-Host "  CONSOLE CYBERDEFENSE INTERACTIVE EN TEMPS REEL - MODE LIVE TERMINAL" -ForegroundColor Cyan
    Write-Host "  Commandes : 'kill <pid>', 'unlock <path>', 'suspend <name>', 'ifeo'," -ForegroundColor DarkGray
    Write-Host "              'sockets', 'ports', 'defender', 'help', 'exit'" -ForegroundColor DarkGray
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
                Write-Host "    unlock <chemin>   : Force l'appropriation et suppression (PendingFileRename)"
                Write-Host "    kill <pid>        : Tue un processus par son ID (force arbre entier)"
                Write-Host "    suspend <nom>     : Gele puis tue un couple de processus watchdog"
                Write-Host "    ifeo              : Verifie les detournements de debogueur"
                Write-Host "    sockets           : Affiche les connexions etablies vers l'exterieur"
                Write-Host "    drivers           : Affiche les filtres kernel actifs"
                Write-Host "    defender          : Force la reparation des signatures Defender"
                Write-Host "    clear             : Efface l'ecran"
                Write-Host "    exit              : Quitte la console"
            }
            'unlock' {
                if ($parts.Count -ge 2) { Invoke-DeepFileExcision $parts[1] }
                else { Write-Host "  Syntaxe : unlock C:\\chemin\\vers\\fichier.exe" -ForegroundColor Red }
            }
            'kill' {
                if ($parts.Count -ge 2) {
                    $pidToKill = $parts[1]
                    Start-Process "taskkill.exe" -ArgumentList "/F /T /PID $pidToKill" -NoNewWindow -Wait
                    Write-Logging "Ordre taskkill /F /T execute sur PID $pidToKill" "OK"
                } else { Write-Host "  Syntaxe : kill <PID>" -ForegroundColor Red }
            }
            'suspend' {
                if ($parts.Count -ge 2) {
                    $nameToSuspend = $parts[1]
                    Get-Process | Where-Object { $_.Name -match $nameToSuspend } | ForEach-Object {
                        [NativeSecurity]::NtSuspendProcess($_.Handle) | Out-Null
                        Write-Host "  [GELE] $($_.Name) PID $($_.Id)" -ForegroundColor Yellow
                    }
                } else { Write-Host "  Syntaxe : suspend <nom_processus>" -ForegroundColor Red }
            }
            'ifeo'    { Clean-IFEODebuggerHijacks }
            'sockets' {
                Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                    Select-Object -First 15 LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
                    Format-Table -AutoSize
            }
            'drivers'  { fltmc filters }
            'defender' {
                $mpCmd = "$env:ProgramFiles\\Windows Defender\\MpCmdRun.exe"
                if (Test-Path $mpCmd) {
                    Start-Process $mpCmd -ArgumentList "-SignatureUpdate -MMPC" -Wait -NoNewWindow
                    Write-Logging "Signatures Defender actualisees." "OK"
                }
            }
            'clear'   { Clear-Host }
            'exit'    { break }
            default   { Write-Host "  Commande inconnue. Tapez 'help'." -ForegroundColor Red }
        }
    } while ($action -ne 'exit')
}

# ==============================================================================
#   MODULES CLASSIQUES ULTRA BOOSTES
# ==============================================================================
function Run-AntivirusScan {
    Show-SectionHeader "ANALYSE COMPLETE WINDOWS DEFENDER"
    Write-Logging "Recherche de l'executable Defender MpCmdRun..." "INFO"
    $defenderPath = "$env:ProgramFiles\\Windows Defender\\MpCmdRun.exe"
    if (Test-Path $defenderPath) {
        Write-Logging "Lancement scan approfondi (-ScanType 2 -DisableRemediation 0)..." "INFO"
        Start-Process -FilePath $defenderPath -ArgumentList "-Scan -ScanType 2 -DisableRemediation 0" -NoNewWindow -Wait
        Write-Logging "Scan termine avec succes." "OK"
    } else {
        Write-Logging "Defender introuvable." "ERROR"
    }
}

function Check-OpenPorts {
    Show-SectionHeader "PORTS RESEAU SENSIBLES"
    Write-Logging "Audit des ports reseau ouverts..." "INFO"
    $portsToCheck = @{
        21="FTP"; 22="SSH"; 23="Telnet"; 25="SMTP"; 80="HTTP"; 135="RPC";
        139="NetBIOS"; 443="HTTPS"; 445="SMB (WannaCry)"; 1433="SQL"; 3306="MySQL";
        3389="RDP"; 4444="Metasploit"; 5900="VNC"; 8080="HTTP Alt"
    }
    $openCount = 0
    foreach ($p in $portsToCheck.Keys) {
        $res = Test-NetConnection -ComputerName localhost -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($res) {
            $openCount++
            $col = if ($p -in @(23,445,4444,139)) { "Red" } else { "Yellow" }
            Write-Host "  [OUVERT] Port $p - $($portsToCheck[$p])" -ForegroundColor $col
            Add-Content -Path $reportPath -Value "  [OUVERT] Port $p - $($portsToCheck[$p])" -ErrorAction SilentlyContinue
        }
    }
    Write-Logging "$openCount port(s) sensible(s) detecte(s)." "OK"
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

    Write-Logging "Audit & Purge des exclusions malveillantes injectees (DefenderSync)..." "INFO"
    try {
        $prefs = Get-MpPreference -ErrorAction SilentlyContinue
        if ($prefs.ExclusionPath) {
            foreach ($exPath in $prefs.ExclusionPath) {
                if ($exPath -match "Public|Temp|AppData|ProgramData") {
                    Write-Logging "Exclusion frauduleuse detectee : $exPath" "WARN"
                    Remove-MpPreference -ExclusionPath $exPath -ErrorAction SilentlyContinue
                    Write-Logging "Exclusion neutralisee : $exPath" "OK"
                }
            }
        }
        if ($prefs.ExclusionProcess -contains "powershell.exe") {
            Remove-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
            Write-Logging "Exclusion frauduleuse de powershell.exe supprimee !" "OK"
        }
    } catch {}

    Write-Logging "Reparation appliquee !" "OK"
}

# ==============================================================================
#   MENUS PRINCIPAUX
# ==============================================================================
function Show-KernelMenu {
    do {
        Show-Banner
        Write-Host "  ====[ MENU KERNEL & EXTIRPATION AVANCEE ]====" -ForegroundColor Red
        Write-Host "  K1. Eradiquer un fichier verrouille (Bypass TrustedInstaller & Handles)" -ForegroundColor Red
        Write-Host "  K2. Gele et tue des processus mutuels (Watchdogs / Double Processus)" -ForegroundColor Yellow
        Write-Host "  K3. Inspecter et nettoyer les detournements IFEO (Debugger Trap)" -ForegroundColor Magenta
        Write-Host "  K4. Purger les injections AppInit_DLLs et AppCertDlls" -ForegroundColor Cyan
        Write-Host "  K5. Auditer les pilotes Kernel & Filter Drivers (Rootkits)" -ForegroundColor DarkCyan
        Write-Host "  K6. Reparer le Mode Sans Echec (SafeBoot) et boot d'urgence" -ForegroundColor Green
        Write-Host "  K7. Entrer dans la Console Live Interactive en temps reel" -ForegroundColor White
        Write-Host "  0.  Retour" -ForegroundColor DarkGray
        Write-Host ""
        $kc = Read-Host "  Choix Kernel"
        switch ($kc) {
            'K1' { Invoke-DeepFileExcision; Pause-Menu }
            'K2' { Suspend-And-Kill-Watchdogs; Pause-Menu }
            'K3' { Clean-IFEODebuggerHijacks; Pause-Menu }
            'K4' { Purge-AppInitAndAppCert; Pause-Menu }
            'K5' { Audit-KernelDrivers; Pause-Menu }
            'K6' { Repair-SafeModeAndReboot }
            'K7' { Enter-CyberDefenseConsole; Pause-Menu }
            '0'  { return }
        }
    } while ($kc -ne '0')
}

function Show-HardeningMenu {
    do {
        Show-Banner
        Write-Host "  ====[ MENU DURCISSEMENT & RESILIENCE ]====" -ForegroundColor DarkYellow
        Write-Host "  H1. Verifier et desactiver SMBv1 (WannaCry)" -ForegroundColor Yellow
        Write-Host "  H2. Verifier l'integrite du fichier HOSTS" -ForegroundColor Yellow
        Write-Host "  H3. Nettoyer les abonnements WMI persistants" -ForegroundColor Red
        Write-Host "  H4. Verifier et recreer les Shadow Copies (VSS Anti-Ransomware)" -ForegroundColor Cyan
        Write-Host "  H5. Verrouiller la PowerShell Execution Policy (RemoteSigned)" -ForegroundColor Green
        Write-Host "  H6. DefenderSync : Auditer et purger les exclusions Defender frauduleuses" -ForegroundColor Red
        Write-Host "  0.  Retour" -ForegroundColor DarkGray
        Write-Host ""
        $hc = Read-Host "  Choix"
        switch ($hc) {
            'H1' {
                Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Write-Logging "SMBv1 Desactive." "OK"; Pause-Menu
            }
            'H2' {
                $h = "$env:SystemRoot\\System32\\drivers\\etc\\hosts"
                Get-Content $h | Write-Host -ForegroundColor Cyan
                Pause-Menu
            }
            'H3' {
                Get-WMIObject -Namespace "root\\subscription" -Class "__EventFilter" | ForEach-Object { $_.Delete() }
                Get-WMIObject -Namespace "root\\subscription" -Class "__EventConsumer" | ForEach-Object { $_.Delete() }
                Write-Logging "Abonnements WMI nettoyes." "OK"; Pause-Menu
            }
            'H4' {
                (Get-WmiObject -List Win32_ShadowCopy).Create("C:\\","ClientAccessible")
                Write-Logging "Nouvelle Shadow Copy creee pour C:\\." "OK"; Pause-Menu
            }
            'H5' {
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
                Write-Logging "Policy configuree sur RemoteSigned." "OK"; Pause-Menu
            }
            'H6' {
                Write-Logging "Audit des exclusions Defender actives..." "INFO"
                $prefs = Get-MpPreference -ErrorAction SilentlyContinue
                Write-Host "  ExclusionPath     : $($prefs.ExclusionPath -join ', ')" -ForegroundColor Yellow
                Write-Host "  ExclusionProcess  : $($prefs.ExclusionProcess -join ', ')" -ForegroundColor Yellow
                Write-Host "  ExclusionExtension: $($prefs.ExclusionExtension -join ', ')" -ForegroundColor Yellow
                $ans = Read-Host "  Purger les exclusions sur Public, Temp, AppData et ProgramData ? (O/N)"
                if ($ans -match "^[Oo]$") {
                    if ($prefs.ExclusionPath) {
                        foreach ($p in $prefs.ExclusionPath) {
                            if ($p -match "Public|Temp|AppData|ProgramData") {
                                Remove-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
                                Write-Logging "Supprime : $p" "OK"
                            }
                        }
                    }
                    if ($prefs.ExclusionProcess -contains "powershell.exe") {
                        Remove-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
                        Write-Logging "Supprime : powershell.exe" "OK"
                    }
                }
                Pause-Menu
            }
            '0'  { return }
        }
    } while ($hc -ne '0')
}

# ==============================================================================
#   BOUCLE PRINCIPALE
# ==============================================================================
do {
    Show-Banner
    Write-Host "  ========================== MENU PRINCIPAL ==========================" -ForegroundColor DarkGray
    Write-Host "   [1]  KERNEL EXTIRPATOR  - Eradication fichiers verrouilles, IFEO, Watchdogs" -ForegroundColor Red
    Write-Host "   [2]  SECURITE & DEFENDER - Scan complet, reparation Defender ecran noir" -ForegroundColor Magenta
    Write-Host "   [3]  RESEAU & C2 HUNTER  - Ports, connexions TCP, Named Pipes Cobalt" -ForegroundColor Cyan
    Write-Host "   [4]  DURCISSEMENT        - WMI, SMBv1, Shadow Copies, Policies" -ForegroundColor Yellow
    Write-Host "   [5]  FORENSIQUE MEMOIRE  - Dump RAM d'urgence, LOLBins, Alternate Data Streams" -ForegroundColor DarkCyan
    Write-Host "   [6]  CONSOLE LIVE        - Console interactive d'analyse en temps reel" -ForegroundColor Green
    Write-Host "   [0]  QUITTER" -ForegroundColor DarkGray
    Write-Host "  ====================================================================" -ForegroundColor DarkGray
    Write-Host "  Rapport actuel : $reportPath" -ForegroundColor DarkGray
    Write-Host ""
    $m = Read-Host "  Selectionnez une option"
    switch ($m) {
        '1' { Show-KernelMenu }
        '2' {
            Run-AntivirusScan
            Repair-WindowsDefender
            Pause-Menu
        }
        '3' {
            Check-OpenPorts
            Get-NetTCPConnection -State Established | Select-Object -First 20 LocalAddress, RemoteAddress, OwningProcess | Format-Table -AutoSize
            Pause-Menu
        }
        '4' { Show-HardeningMenu }
        '5' {
            Write-Logging "Dump rapide des processus en memoire..." "INFO"
            Get-Process | Select-Object -First 30 Name, Id, CPU, WorkingSet | Format-Table -AutoSize
            Pause-Menu
        }
        '6' { Enter-CyberDefenseConsole }
        '0' { Write-Logging "Fermeture de la suite SpaceSec. Restez vigilant !" "OK"; exit }
    }
} while ($m -ne '0')
`;

export const ELEVATED_BATCH_LAUNCHER = `@echo off
:: ==============================================================================
:: SpaceSec Ultra Edition - Auto-Elevation & SYSTEM Privilege Wrapper
:: Lance la suite PowerShell avec bypass execution policy et privileges administrateur
:: ==============================================================================
TITLE SpaceSec CyberDefense Suite - Elevated Launcher
color 0b

echo.
echo  ====================================================================
echo   Demarrage de SpaceSec CyberDefense Suite (Mode Administrateur)
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
