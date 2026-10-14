# Space Security - Guide de Compilation du Pilote Noyau Ring-0 & Signature WHQL

Ce document décrit l'architecture, la chaîne de compilation et les exigences de signature de Microsoft pour le pilote Minifilter Ring-0 (`spacesec_minifilter.sys`).

---

## 1. La Frontière Architecturale : Ring 0 vs Ring 3 (Userland)

Sous Windows x64 (10 et 11), les technologies suivantes interdisent strictement l'accès au noyau depuis l'espace utilisateur :
1. **Microsoft PatchGuard (Kernel Patch Protection - KPP)** : Surveille l'intégrité des structures critiques (SSDT, IDT, GDT, et tables système). Tout accès direct depuis le mode utilisateur provoque immédiatement un BugCheck (BSOD `CRITICAL_STRUCTURE_CORRUPTION`).
2. **Driver Signature Enforcement (DSE)** : Empêche le chargement de tout pilote qui n'est pas signé numériquement par Microsoft.
3. **PspCidTable vs ActiveProcessLinks** : Les rootkits de type DKOM (Direct Kernel Object Manipulation) déchaînent le bloc `EPROCESS` de la liste doublement chaînée `ActiveProcessLinks` du noyau. Depuis le mode utilisateur (Ring 3), aucune API légale (`Toolhelp32`, `NtQuerySystemInformation`, `WMI`) ne peut inspecter `PspCidTable` ou la mémoire physique directement.

**C'est pourquoi SpaceSec implémente une architecture à double niveau :**
- **Niveau Ring 0 (Pilote Minifilter `spacesec_minifilter.sys`)** : Interception au ras du noyau avant l'exécution du moindre thread ou IRP fichier.
- **Niveau Ring 3 (Moteur Natif `SpaceSecNativeEngine`)** : Détection heuristique croisée VAD (Virtual Address Descriptors), détection de divergences de descripteurs (Cross-View Discrepancy), détection d'usurpation de binaires système (Svchost hors System32).

---

## 2. Capacités du Pilote Kernel (`spacesec_minifilter.c`)

| Fonctionnalité | Routine d'Interception Kernel | But de Sécurité |
| :--- | :--- | :--- |
| **Interception de Processus** | `PsSetCreateProcessNotifyRoutineEx` | Neutralise les malwares avant la création de leur thread initial. |
| **Audit DKOM & PspCidTable** | Énumération des blocs `EPROCESS` | Détecte les processus déliés d'ActiveProcessLinks. |
| **Blocage d'Injection Mémoire** | `PsSetCreateThreadNotifyRoutine` | Empêche `CreateRemoteThread` et les attaques par Process Hollowing. |
| **Protection PPL LSASS / CSRSS** | `ObRegisterCallbacks` | Retire les droits `PROCESS_VM_READ/WRITE` pour bloquer Mimikatz. |
| **Minifilter Système de Fichiers** | `FltRegisterFilter` (Altitude `320500`) | Bloque les IRP d'écriture de rançongiciels et les drops de rootkits. |

---

## 3. Prérequis de Compilation (Windows WDK)

1. Installer **Visual Studio 2022** (avec les composants C++ Desktop).
2. Installer le **Windows 11 SDK** (build 22621 ou supérieur).
3. Installer le **Windows Driver Kit (WDK)** assorti.
4. Ouvrir l'invite **x64 Native Tools Command Prompt for VS 2022**.

---

## 4. Compilation Locale

Exécutez le script fourni `build-driver.cmd` :

```cmd
cd src\server\native
build-driver.cmd
```

Le script invoque `MSBuild` pour produire :
- `spacesec_minifilter.sys` (binaire du pilote compilé x64)
- `spacesec_minifilter.inf` (script d'installation du service Minifilter)
- `spacesec_minifilter.cat` (catalogue de signature)

---

## 5. Mode Test (Développement / Homologation)

Pour charger le pilote sans certificat WHQL commercial :

```cmd
:: 1. Activer le mode TestSigning de Windows
bcdedit /set testsigning on

:: 2. Créer et installer un certificat auto-signé de test
makecert -r -pe -ss SpaceSecCertStore -n "CN=SpaceSec Test Driver" SpaceSecTest.cer
certmgr.exe -add SpaceSecTest.cer -s -r localMachine root
certmgr.exe -add SpaceSecTest.cer -s -r localMachine trustedpublisher

:: 3. Signer le pilote
signtool sign /v /s SpaceSecCertStore /n "SpaceSec Test Driver" /t http://timestamp.digicert.com spacesec_minifilter.sys

:: 4. Installer le service Minifilter
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 .\spacesec_minifilter.inf

:: 5. Démarrer le pilote
fltmc load SpaceSecMinifilter
```

Vérifiez l'altitude et le statut avec :
```cmd
fltmc filters
```
Vous devriez voir `SpaceSecMinifilter` à l'altitude `320500` (Catégorie FSFilter Anti-Virus).

---

## 6. Déploiement en Production : Signature WHQL Microsoft

Pour charger le pilote sur des machines de production Windows 10/11 avec Secure Boot activé :
1. Obtenir un **Certificat Code Signing EV (Extended Validation)** auprès d'une autorité reconnue (DigiCert, Sectigo).
2. Enregistrer l'organisation sur le portail **Microsoft Partner Center** (Hardware Developer Program).
3. Soumettre le package de pilote pour **Attestation Signing** (HLK / WHQL).
4. Télécharger le package `.cat` et `.sys` contre-signé par l'autorité racine Microsoft (`Microsoft Windows Hardware Compatibility Publisher`).
