import JSZip from 'jszip';
import { BOOSTED_POWERSHELL_SCRIPT, ELEVATED_BATCH_LAUNCHER, EMERGENCY_SAFEBOOT_LAUNCHER } from '../data/powershellScript';
import { CSHARP_EXTIRPATOR_CODE } from '../data/csharpExtirpator';

export const README_GUIDE_CONTENT = `================================================================================
  SPACESEC CYBERDEFENSE SUITE & KERNEL EXTIRPATOR v3.0 - EDITION ULTRA
  Auteur original : Space [Goat Asta] | Boostee pour Ingenieurs Cybersecurite
================================================================================

CONTENU DE CE PACK ZIP :
-----------------------
1. SpaceSecurity_ULTRA_v3_Kernel.ps1
   -> Script principal PowerShell ultra-booste.
   -> Contient 25+ modules de cyberdefense :
      - Eradication des fichiers verrouilles par TrustedInstaller / Handles noyau
      - Destruction planifiee au boot via Session Manager (PendingFileRenameOperations)
      - Suspension atomique de watchdogs / processus mutuels (NtSuspendProcess P/Invoke)
      - Reparation de Windows Defender, vidage des cles de sabotage et mise a jour
      - Purge des pieges de debogueur IFEO (Image File Execution Options)
      - Traque des connexions C2 (Metasploit 4444, Cobalt Strike Named Pipes)
      - Detection des LOLBins (certutil, bitsadmin, mshta) et flux NTFS alternatifs (ADS)
      - Desactivation SMBv1, purge abonnements WMI et creation de Shadow Copies VSS
      - Mode Console Interactive en temps reel integre directement dans PowerShell

2. KernelFileExtirpator.cs (Module C# Natif)
   -> Code source C# de production autonome avec MoveFileEx P/Invoke,
      elevation SeDebug/SeTakeOwnership/SeRestore/SeBackup, bypass TrustedInstaller
      via takeown/icacls/SetNamedSecurityInfo, killer de watchdogs via NtSuspendProcess
      et Restart Manager API.

3. RunAs_SpaceSecurity_Admin.bat
   -> Lanceur d'auto-elevation en Administrateur.
   -> Contourne automatiquement la restriction d'execution (-ExecutionPolicy Bypass).
   -> Recommande pour lancer la suite sans taper de commande.

4. Emergency_SafeBoot_Clean.bat
   -> Outil de secours pour configurer un redemarrage chirurgical en Mode Sans Echec
      minimal (via bcdedit) si un malware bloque completement la session normale.

--------------------------------------------------------------------------------
MODE D'EMPLOI ET LANCEMENT RAPIDE :
--------------------------------------------------------------------------------
METHODE A (Recommandee, le plus simple) :
1. Decompressez l'archive ZIP dans un dossier (ex: sur votre Bureau).
2. Faites un CLIC DROIT sur "RunAs_SpaceSecurity_Admin.bat".
3. Choisissez "Executer en tant qu'administrateur".
4. Le script s'ouvre dans une fenetre securisee.

METHODE B (Ligne de commande PowerShell directe) :
1. Ouvrez PowerShell en tant qu'Administrateur.
2. Rendez-vous dans le dossier dezippe :
   cd "$env:USERPROFILE\\Desktop\\SpaceSec"
3. Lancez la commande suivante :
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\SpaceSecurity_ULTRA_v3_Kernel.ps1

--------------------------------------------------------------------------------
COMMENT DETRUIRE UN FICHIER VERROUILLE QUE WINDOWS REFUSE D'EFFACER :
--------------------------------------------------------------------------------
1. Dans le menu de la suite, tapez "1" (KERNEL EXTIRPATOR).
2. Choisissez "K1" (Eradiquer un fichier verrouille).
3. Collez le chemin complet du fichier (ex: C:\\Windows\\System32\\drivers\\malware.sys).
4. Le script va :
   - Reinitialiser les attributs de fichier (Normal).
   - Prendre possession du fichier grace aux privileges SeTakeOwnershipPrivilege (takeown).
   - Vous accorder le controle total en ecrasant les restrictions TrustedInstaller (icacls).
   - Tuer l'arbre de processus associe.
   - Si le fichier reste maintenu en memoire par un pilote, l'inscrire dans
     PendingFileRenameOperations et l'ecraser a 0 octet.
   - Au prochain redemarrage, Windows detruira physiquement le fichier avant le chargement
     de tout logiciel malveillant !

--------------------------------------------------------------------------------
SUPPORT & RAPPORT D'AUDIT :
--------------------------------------------------------------------------------
A chaque execution, un rapport detaille horodate est automatiquement genere sur
votre Bureau :
  -> SpaceSecurity_UltraReport_YYYYMMDD_HHMMSS.txt
  -> SpaceSecurity_Kernel_Log.txt
================================================================================
`;

export async function generateAndDownloadZip(): Promise<void> {
  const zip = new JSZip();

  // Add files to zip
  zip.file('SpaceSecurity_ULTRA_v3_Kernel.ps1', BOOSTED_POWERSHELL_SCRIPT);
  zip.file('KernelFileExtirpator.cs', CSHARP_EXTIRPATOR_CODE);
  zip.file('RunAs_SpaceSecurity_Admin.bat', ELEVATED_BATCH_LAUNCHER);
  zip.file('Emergency_SafeBoot_Clean.bat', EMERGENCY_SAFEBOOT_LAUNCHER);
  zip.file('README_MODE_D_EMPLOI.txt', README_GUIDE_CONTENT);

  // Generate ZIP blob
  const zipBlob = await zip.generateAsync({
    type: 'blob',
    compression: 'DEFLATE',
    compressionOptions: { level: 9 },
  });

  // Trigger client-side download
  const url = URL.createObjectURL(zipBlob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'SpaceSec_CyberDefense_Ultra_v3.zip';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
