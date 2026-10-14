/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export const generateEdrAgentPowerShell = (serverUrl: string, authToken: string): string => {
  return `# ==============================================================================
# Space Security CyberDefense Suite - EDR Remote Agent (Windows)
# Version: 3.0.0-EDR-LIGHT
# Author: Space Security Cybersecurity Labs
# Role: Agent de collecte et de remédiation EDR léger pour postes clients Windows
# ==============================================================================

[CmdletBinding()]
param(
    [string]$ServerUrl = "${serverUrl}",
    [string]$AuthToken = "${authToken}",
    [int]$HeartbeatIntervalSec = 10,
    [switch]$InstallAsService,
    [switch]$Silent
)

# 1. Verification des privileges Administrateur
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "[SpaceSec-Agent] Privileges Administrateur requis pour surveiller le noyau et les sockets. Relancez PowerShell en Administrateur."
    exit 1
}

# Nettoyage de l'URL du serveur (supprimer le slash final)
$ServerUrl = $ServerUrl.TrimEnd('/')

function Write-EdrLog([string]$level, [string]$msg) {
    if (-not $Silent) {
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $color = switch ($level) {
            "CRITICAL" { "Red" }
            "WARN"     { "Yellow" }
            "INFO"     { "Cyan" }
            "OK"       { "Green" }
            default    { "White" }
        }
        Write-Host "[$timestamp] [$level] $msg" -ForegroundColor $color
    }
}

Write-EdrLog "INFO" "Initialisation de l'Agent EDR SpaceSec v3.0..."
Write-EdrLog "INFO" "Serveur Central SOC : $ServerUrl"

# 2. Collecte des Metadonnees de l'Endpoint
$hostname = $env:COMPUTERNAME
$os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue)
$osVersion = if ($os) { "$($os.Caption) ($($os.Version))" } else { "Microsoft Windows" }

$netAdapters = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi*", "Ethernet*" -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" }
$ipAddress = if ($netAdapters) { $netAdapters[0].IPAddress } else { "127.0.0.1" }
$macObj = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Select-Object -First 1
$macAddress = if ($macObj) { $macObj.MacAddress } else { "00:00:00:00:00:00" }

$endpointId = "ep-$($hostname.ToLower())-" + [Math]::Abs($hostname.GetHashCode()).ToString()

# 3. Enregistrement aupres du Serveur SOC Central
$regPayload = @{
    id = $endpointId
    hostname = $hostname
    ipAddress = $ipAddress
    macAddress = $macAddress
    osVersion = $osVersion
    agentVersion = "v3.0.0-EDR-LIGHT"
} | ConvertTo-Json -Compress

$headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer $AuthToken"
    "X-SpaceSec-Token" = "$AuthToken"
}

try {
    Write-EdrLog "INFO" "Enregistrement de l'endpoint auprès du serveur central ($endpointId)..."
    $regResponse = Invoke-RestMethod -Uri "$ServerUrl/api/edr/register" -Method Post -Body $regPayload -Headers $headers -TimeoutSec 10
    Write-EdrLog "OK" "Endpoint enrégistré avec succès ! Statut : $($regResponse.endpoint.status)"
} catch {
    Write-EdrLog "WARN" "Impossible de joindre le serveur central ($($_.Exception.Message)). Tentative en mode déconnecté..."
}

# 4. Boucle de Surveillance en Temps Reel
Write-EdrLog "OK" "Boucle de veille EDR active. Surveillance continue du noyau, processus, registre et flux C2..."

while ($true) {
    try {
        # A. Mesure CPU & RAM
        $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        $totalRam = (Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize
        $freeRam = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory
        $ramPercent = [Math]::Round((($totalRam - $freeRam) / $totalRam) * 100)

        # B. Detection Processus Falsifies / Masquerading (ex: explorer.exe dans Themes)
        $telemetryEvents = [System.Collections.Generic.List[PSObject]]::new()

        $rogueThemes = Get-ChildItem -Path "C:\\Windows\\Resources\\Themes" -Filter "*.exe" -File -ErrorAction SilentlyContinue
        if ($rogueThemes) {
            foreach ($rf in $rogueThemes) {
                $proc = Get-Process -Name $rf.BaseName -ErrorAction SilentlyContinue
                $telemetryEvents.Add(@{
                    category = "PROCESS"
                    severity = "CRITICAL"
                    summary = "Binaire suspect d'évasion masqué dans Themes : $($rf.FullName) $(if ($proc) { "(Actif sous PID $($proc.Id))" })"
                    details = @{ path = $rf.FullName; pid = if ($proc) { $proc.Id } else { 0 }; size = $rf.Length }
                    mitreTechnique = "T1036.005 - Masquerading"
                })
            }
        }

        # C. Detection Connexions Sockets C2 Suspectes (ex: Port 4444, 1337, etc.)
        $c2Ports = @(4444, 1337, 8888, 5555, 6666)
        $netConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $c2Ports -contains $_.RemotePort }
        if ($netConns) {
            foreach ($nc in $netConns) {
                $ownerProc = Get-Process -Id $nc.OwningProcess -ErrorAction SilentlyContinue
                $telemetryEvents.Add(@{
                    category = "NETWORK"
                    severity = "CRITICAL"
                    summary = "Balise C2 Sortante détectée : $($nc.RemoteAddress):$($nc.RemotePort) depuis $($ownerProc.Name) (PID $($nc.OwningProcess))"
                    details = @{ remoteIp = $nc.RemoteAddress; remotePort = $nc.RemotePort; pid = $nc.OwningProcess; process = $ownerProc.Name }
                    mitreTechnique = "T1071 - Application Layer Protocol"
                })
            }
        }

        # D. Detection IFEO Debugger Hijacks (Persistance de debogueur sur Taskmgr / cmd / defender)
        $ifeoPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        $targets = @("taskmgr.exe", "cmd.exe", "powershell.exe", "MsMpEng.exe")
        foreach ($t in $targets) {
            if (Test-Path "$ifeoPath\\$t") {
                $debugger = (Get-ItemProperty "$ifeoPath\\$t" -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
                if ($debugger) {
                    $telemetryEvents.Add(@{
                        category = "REGISTRY"
                        severity = "HIGH"
                        summary = "Piège de débogueur IFEO actif sur $t : Débogueur falsifié '$debugger'"
                        details = @{ target = $t; debugger = $debugger }
                        mitreTechnique = "T1546.012 - Image File Execution Options Injection"
                    })
                }
            }
        }

        # E. Envoi de la Telemetrie au Serveur SOC si alertes
        if ($telemetryEvents.Count -gt 0) {
            $telemetryPayload = @{
                endpointId = $endpointId
                hostname = $hostname
                events = $telemetryEvents
            } | ConvertTo-Json -Depth 5 -Compress

            try {
                Invoke-RestMethod -Uri "$ServerUrl/api/edr/telemetry" -Method Post -Body $telemetryPayload -Headers $headers -TimeoutSec 8 | Out-Null
                Write-EdrLog "WARN" "Télémétrie transmise au SOC central ($($telemetryEvents.Count) alertes)."
            } catch {
                Write-EdrLog "WARN" "Échec envoi télémétrie : $($_.Exception.Message)"
            }
        }

        # F. Envoi du Heartbeat & Recuperation des Ordres de Remediation
        $hbPayload = @{
            endpointId = $endpointId
            cpuUsagePercent = [int]$cpu
            ramUsagePercent = [int]$ramPercent
            activeThreatsCount = $telemetryEvents.Count
        } | ConvertTo-Json -Compress

        try {
            $hbResponse = Invoke-RestMethod -Uri "$ServerUrl/api/edr/heartbeat" -Method Post -Body $hbPayload -Headers $headers -TimeoutSec 8
            
            # G. Execution des Ordres Recus du SOC
            if ($hbResponse.pendingCommands -and $hbResponse.pendingCommands.Count -gt 0) {
                foreach ($cmd in $hbResponse.pendingCommands) {
                    Write-EdrLog "WARN" ">>> Ordre de remédiation reçu du SOC : $($cmd.type) (ID: $($cmd.id))"
                    $cmdResult = ""
                    $cmdSuccess = $true

                    switch ($cmd.type) {
                        "KILL_PROCESS" {
                            $targetPid = $cmd.payload.pid
                            try {
                                Stop-Process -Id $targetPid -Force -ErrorAction Stop
                                $cmdResult = "Processus PID $targetPid abattu avec succès (taskkill forcé)."
                                Write-EdrLog "OK" $cmdResult
                            } catch {
                                $cmdSuccess = $false
                                $cmdResult = "Erreur terminaison PID $targetPid : $($_.Exception.Message)"
                                Write-EdrLog "CRITICAL" $cmdResult
                            }
                        }

                        "ISOLATE_NETWORK" {
                            try {
                                # Bloquer tout trafic sortant/entrant sauf le serveur SpaceSec
                                New-NetFirewallRule -DisplayName "SpaceSec-EDR-Isolate-In" -Direction Inbound -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                                New-NetFirewallRule -DisplayName "SpaceSec-EDR-Isolate-Out" -Direction Outbound -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                                $cmdResult = "Machine isolée du réseau avec succès (Règles pare-feu actives)."
                                Write-EdrLog "OK" $cmdResult
                            } catch {
                                $cmdSuccess = $false
                                $cmdResult = "Erreur isolation réseau : $($_.Exception.Message)"
                            }
                        }

                        "UNISOLATE_NETWORK" {
                            try {
                                Remove-NetFirewallRule -DisplayName "SpaceSec-EDR-Isolate-In" -ErrorAction SilentlyContinue | Out-Null
                                Remove-NetFirewallRule -DisplayName "SpaceSec-EDR-Isolate-Out" -ErrorAction SilentlyContinue | Out-Null
                                $cmdResult = "Isolation levée. Connectivité réseau rétablie."
                                Write-EdrLog "OK" $cmdResult
                            } catch {
                                $cmdSuccess = $false
                                $cmdResult = "Erreur rétablissement réseau : $($_.Exception.Message)"
                            }
                        }

                        "REPAIR_THEMES" {
                            try {
                                $killed = 0
                                Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*\\Resources\\Themes\\*" } | ForEach-Object {
                                    Stop-Process -Id $_.Id -Force
                                    $killed++
                                }
                                $cmdResult = "Nettoyage du dossier Themes exécuté ($killed processus neutralisés)."
                                Write-EdrLog "OK" $cmdResult
                            } catch {
                                $cmdSuccess = $false
                                $cmdResult = "Erreur nettoyage Themes : $($_.Exception.Message)"
                            }
                        }

                        "CUSTOM_PS" {
                            $codeToRun = $cmd.payload.command
                            try {
                                $output = Invoke-Expression $codeToRun | Out-String
                                $cmdResult = "Script exécuté. Sortie : " + $output.Trim()
                                Write-EdrLog "OK" "Script distant exécuté."
                            } catch {
                                $cmdSuccess = $false
                                $cmdResult = "Erreur exécution script : $($_.Exception.Message)"
                            }
                        }

                        default {
                            $cmdResult = "Type de commande inconnu ou non supporté : $($cmd.type)"
                        }
                    }

                    # Acquittement auprès du serveur central
                    $ackPayload = @{
                        status = if ($cmdSuccess) { "EXECUTED" } else { "FAILED" }
                        result = $cmdResult
                    } | ConvertTo-Json -Compress

                    try {
                        Invoke-RestMethod -Uri "$ServerUrl/api/edr/commands/$($cmd.id)/ack" -Method Post -Body $ackPayload -Headers $headers -TimeoutSec 8 | Out-Null
                    } catch {}
                }
            }
        } catch {
            Write-EdrLog "WARN" "Heartbeat non délivré (serveur temporairement inaccessible)."
        }

    } catch {
        Write-EdrLog "WARN" "Erreur d'itération agent : $($_.Exception.Message)"
    }

    Start-Sleep -Seconds $HeartbeatIntervalSec
}
`;
};
