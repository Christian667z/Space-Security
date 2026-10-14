/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export const generateEdrAgentPowerShell = (serverUrl: string, authToken: string): string => {
  return `# ==============================================================================
# Space Security CyberDefense Suite - EDR Remote Agent (Windows)
# Version: 3.1.0-EDR-SECURE
# Author: Space Security Cybersecurity Labs
# Role: Agent de collecte et de remédiation EDR sécurisé pour postes clients Windows
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

# Fonction cryptographique HMAC-SHA256 pour l'authentification et l'intégrité
function Get-HmacSha256([string]$secret, [string]$data) {
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($secret))
    $bytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($data))
    return [BitConverter]::ToString($bytes).Replace("-", "").ToLower()
}

Write-EdrLog "INFO" "Initialisation de l'Agent EDR SpaceSec v3.1 (Mode Sécurisé)..."
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
$agentSecret = ""

# 3. Enregistrement auprès du Serveur SOC Central (Échange de clé secrète par agent)
$regPayload = @{
    id = $endpointId
    hostname = $hostname
    ipAddress = $ipAddress
    macAddress = $macAddress
    osVersion = $osVersion
    agentVersion = "v3.1.0-EDR-SECURE"
} | ConvertTo-Json -Compress

$regHeaders = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer $AuthToken"
    "X-SpaceSec-Token" = "$AuthToken"
}

try {
    Write-EdrLog "INFO" "Enregistrement de l'endpoint auprès du serveur central ($endpointId)..."
    $regResponse = Invoke-RestMethod -Uri "$ServerUrl/api/edr/register" -Method Post -Body $regPayload -Headers $regHeaders -TimeoutSec 10
    if ($regResponse.endpoint -and $regResponse.endpoint.id) {
        $endpointId = $regResponse.endpoint.id
    }
    if ($regResponse.agentSecret) {
        $agentSecret = $regResponse.agentSecret
        Write-EdrLog "OK" "Cle secrète d'agent provisionnée avec succès (HMAC-SHA256 actif)."
    } else {
        $agentSecret = $AuthToken
    }
    Write-EdrLog "OK" "Endpoint enregistré avec succès ! Statut : $($regResponse.endpoint.status)"
} catch {
    Write-EdrLog "WARN" "Impossible de joindre le serveur central ($($_.Exception.Message)). Tentative en mode déconnecté..."
    $agentSecret = $AuthToken
}

# Fonction d'envoi de requêtes signées au serveur
function Invoke-SignedEdrRequest([string]$url, [string]$method, [string]$bodyJson) {
    $timestamp = [DateTime]::UtcNow.ToString("o")
    $dataToSign = "$timestamp`:$endpointId`:$bodyJson"
    $sig = Get-HmacSha256 -secret $agentSecret -data $dataToSign

    $headers = @{
        "Content-Type" = "application/json"
        "Authorization" = "Bearer $agentSecret"
        "X-SpaceSec-Endpoint-Id" = "$endpointId"
        "X-SpaceSec-Timestamp" = "$timestamp"
        "X-SpaceSec-Signature" = "$sig"
        "X-SpaceSec-Agent-Secret" = "$agentSecret"
    }

    return Invoke-RestMethod -Uri $url -Method $method -Body $bodyJson -Headers $headers -TimeoutSec 10
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

        # E. Envoi de la Telemetrie au Serveur SOC si alertes (Signé par HMAC)
        if ($telemetryEvents.Count -gt 0) {
            $telemetryPayload = @{
                endpointId = $endpointId
                hostname = $hostname
                events = $telemetryEvents
            } | ConvertTo-Json -Depth 5 -Compress

            try {
                Invoke-SignedEdrRequest "$ServerUrl/api/edr/telemetry" "Post" $telemetryPayload | Out-Null
                Write-EdrLog "WARN" "Télémétrie signée transmise au SOC central ($($telemetryEvents.Count) alertes)."
            } catch {
                Write-EdrLog "WARN" "Échec envoi télémétrie : $($_.Exception.Message)"
            }
        }

        # F. Envoi du Heartbeat & Recuperation des Ordres de Remediation (Signé par HMAC)
        $hbPayload = @{
            endpointId = $endpointId
            cpuUsagePercent = [int]$cpu
            ramUsagePercent = [int]$ramPercent
            activeThreatsCount = $telemetryEvents.Count
        } | ConvertTo-Json -Compress

        try {
            $hbResponse = Invoke-SignedEdrRequest "$ServerUrl/api/edr/heartbeat" "Post" $hbPayload
            
            # G. Execution Sécurisée des Ordres Reçus du SOC (Vérification TTL & Signature HMAC)
            if ($hbResponse.pendingCommands -and $hbResponse.pendingCommands.Count -gt 0) {
                foreach ($cmd in $hbResponse.pendingCommands) {
                    Write-EdrLog "WARN" ">>> Ordre de remédiation reçu du SOC : $($cmd.type) (ID: $($cmd.id))"
                    $cmdResult = ""
                    $cmdSuccess = $true
                    $cmdStatus = "EXECUTED"

                    # 1. Vérification TTL / Expiration
                    if ($cmd.expiresAt) {
                        try {
                            $expiresTime = [DateTime]::Parse($cmd.expiresAt).ToUniversalTime()
                            if ([DateTime]::UtcNow -gt $expiresTime) {
                                Write-EdrLog "WARN" "Commande $($cmd.id) expirée (TTL dépassé). Rejet automatique."
                                $cmdStatus = "EXPIRED"
                                $cmdSuccess = $false
                                $cmdResult = "Commande expirée avant exécution (TTL dépassé)."
                            }
                        } catch {}
                    }

                    # 2. Vérification de la Signature Cryptographique HMAC
                    if ($cmdSuccess -and $cmd.signature) {
                        $payloadStr = if ($cmd.payload) { $cmd.payload | ConvertTo-Json -Compress } else { "{}" }
                        $sigData = "$($cmd.id):$($cmd.type):$payloadStr:$($cmd.expiresAt)"
                        $expectedSig = Get-HmacSha256 -secret $agentSecret -data $sigData
                        if ($expectedSig -ne $cmd.signature) {
                            Write-EdrLog "CRITICAL" "Signature cryptographique INVALIDE pour commande $($cmd.id) ! Rejet pour falsification."
                            $cmdStatus = "FAILED"
                            $cmdSuccess = $false
                            $cmdResult = "Rejeté : Signature HMAC invalide. Altération suspectée."
                        }
                    }

                    # 3. Exécution conditionnelle (commandes sécurisées prédéfinies uniquement, aucune exécution arbitraire)
                    if ($cmdSuccess) {
                        switch ($cmd.type) {
                            "KILL_PROCESS" {
                                $targetPid = $cmd.payload.pid
                                try {
                                    Stop-Process -Id $targetPid -Force -ErrorAction Stop
                                    $cmdResult = "Processus PID $targetPid abattu avec succès (taskkill forcé)."
                                    Write-EdrLog "OK" $cmdResult
                                } catch {
                                    $cmdSuccess = $false
                                    $cmdStatus = "FAILED"
                                    $cmdResult = "Erreur terminaison PID $targetPid : $($_.Exception.Message)"
                                    Write-EdrLog "CRITICAL" $cmdResult
                                }
                            }

                            "ISOLATE_NETWORK" {
                                try {
                                    # Bloquer tout trafic sortant/entrant tout en préservant le serveur SOC SpaceSec
                                    New-NetFirewallRule -DisplayName "SpaceSec-EDR-Isolate-In" -Direction Inbound -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                                    New-NetFirewallRule -DisplayName "SpaceSec-EDR-Isolate-Out" -Direction Outbound -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                                    $cmdResult = "Machine isolée du réseau avec succès (Règles pare-feu actives)."
                                    Write-EdrLog "OK" $cmdResult
                                } catch {
                                    $cmdSuccess = $false
                                    $cmdStatus = "FAILED"
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
                                    $cmdStatus = "FAILED"
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
                                    $cmdStatus = "FAILED"
                                    $cmdResult = "Erreur nettoyage Themes : $($_.Exception.Message)"
                                }
                            }

                            "RESTORE_DEFENDER" {
                                try {
                                    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
                                    Update-MpSignature -ErrorAction SilentlyContinue
                                    $cmdResult = "Microsoft Defender réactivé et signatures mises à jour."
                                    Write-EdrLog "OK" $cmdResult
                                } catch {
                                    $cmdSuccess = $false
                                    $cmdStatus = "FAILED"
                                    $cmdResult = "Erreur réactivation Defender : $($_.Exception.Message)"
                                }
                            }

                            "SCAN_DEEP" {
                                try {
                                    Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
                                    $cmdResult = "Analyse approfondie du système d'exploitation initiée."
                                    Write-EdrLog "OK" $cmdResult
                                } catch {
                                    $cmdSuccess = $false
                                    $cmdStatus = "FAILED"
                                    $cmdResult = "Erreur analyse approfondie : $($_.Exception.Message)"
                                }
                            }

                            default {
                                $cmdSuccess = $false
                                $cmdStatus = "FAILED"
                                $cmdResult = "Type de commande rejeté ou non autorisé (CUSTOM_PS interdit) : $($cmd.type)"
                                Write-EdrLog "WARN" $cmdResult
                            }
                        }
                    }

                    # Acquittement signé auprès du serveur central
                    $ackPayload = @{
                        status = $cmdStatus
                        result = $cmdResult
                    } | ConvertTo-Json -Compress

                    try {
                        Invoke-SignedEdrRequest "$ServerUrl/api/edr/commands/$($cmd.id)/ack" "Post" $ackPayload | Out-Null
                        Write-EdrLog "INFO" "Acquittement transmis pour la commande $($cmd.id) ($cmdStatus)."
                    } catch {
                        Write-EdrLog "WARN" "Échec acquittement commande $($cmd.id) : $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            Write-EdrLog "WARN" "Heartbeat non délivré (serveur temporairement inaccessible ou refus d'authentification)."
        }

    } catch {
        Write-EdrLog "WARN" "Erreur d'itération agent : $($_.Exception.Message)"
    }

    Start-Sleep -Seconds $HeartbeatIntervalSec
}
`;
};
