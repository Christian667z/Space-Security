import JSZip from 'jszip';
import { BOOSTED_POWERSHELL_SCRIPT, ELEVATED_BATCH_LAUNCHER, EMERGENCY_SAFEBOOT_LAUNCHER } from '../data/powershellScript';
import { CSHARP_EXTIRPATOR_CODE } from '../data/csharpExtirpator';

export const README_GUIDE_CONTENT = `================================================================================
  SPACESEC CYBERDEFENSE SUITE & KERNEL EXTIRPATOR v3.5 - EDITION ULTRA
  Auteur initial : Space [Goat Asta] | Boostee pour Ingenieurs Cybersecurite
================================================================================

NOUVEAUTES & MENUS 10 A 14 :
-----------------------------
[10] DETECTION PROFONDE :
     - Usurpation de processus Windows (spoofing de nom, parent anormal).
     - Processus caches (recherche brute-force PID 4..65535 vs API Windows).
     - Code injecte en memoire (zones RWX PAGE_EXECUTE_READWRITE & Reflective DLL).
     - Persistance complete (Run, Winlogon, IFEO, LSA, BootExecute, WMI, Startup).
     - Services et pilotes noyau suspects & taches planifiees non signees.
     - Scan heuristique global par score (0 a 100) avec penalites MITRE.

[11] REMEDIATION & QUARANTAINE RESTAURABLE :
     - Quarantaine securisee et restaurable avec manifeste JSON et revocation ACL.
     - Eradication forcee au redemarrage noyau via PendingFileRenameOperations.
     - Redemarrage programme en WinRE (Environnement de Recuperation Windows).
     - Garde-fous certifie Microsoft : verification Authenticode pour empecher la suppression de fichiers systeme.
     - Sauvegarde preventive des processus, cles et services avant toute modification.

[12] DEFENDER AVANCE :
     - Audit et purge des exclusions frauduleuses (chemins Public/Temp, extensions).
     - Lancement de l'analyse hors-ligne Windows Defender Offline (WDO).
     - Activation des regles ASR (Attack Surface Reduction) anti-vol d'identifiants LSASS.
     - Historique detaille des menaces et alertes Defender.

[13] FORENSIQUE & LOGS :
     - Detection des attaques par force brute (Event ID 4625).
     - Detection des tentatives d'effacement de journaux (Event ID 1102 & 104).
     - Detection de creation de comptes admins (Event ID 4720, 4728) et nouveaux services (7045).
     - Collecte de preuves avec hachage cryptographique SHA-256.

[14] RAPPORTS & EXPORTS :
     - Synthese de session interactive en temps reel.
     - Export de rapports HTML moderne sombre, CSV pour tableur et JSON pour SIEM.

CORRECTIFS APPLIQUES DANS CETTE VERSION :
-----------------------------------------
- Menu SOS : V5 declenche desormais le protocole d'urgence reel et V6 connecte la console live.
- Faux positifs : Mots-cles 'rat'/'nc' filtres avec regex et liste blanche (Narrator, Configuration).
- Quarantaine d'abord : Fini les suppressions aveugles; les fichiers sont isoles avec confirmation.
- Snapshot memoire : Renomme 'Snapshot memoire' (evite la fausse promesse d'une image RAM physique).
- Scan de ports : Multithreading avec timeouts courts de 150ms (.NET Sockets).
- Named Pipes : Chemin corrige sur le namespace reel \\\\.\\pipe\\.
- Detection C2 : Exclusion des adresses IP privees RFC 1918 et loopback pour cibler uniquement les balises externes.
- Nettoyage : Prefetch et Temp ne sont plus supprimes automatiquement pour preserver les preuves forensiques.

CONTENU DU PACK :
-----------------
1. SpaceSecurity_ULTRA_v3_Kernel.ps1  - Script principal avec menus 10 a 14.
2. KernelFileExtirpator.cs             - Code source C# natif autonome.
3. RunAs_SpaceSecurity_Admin.bat       - Lanceur avec auto-elevation UAC.
4. Emergency_SafeBoot_Clean.bat        - Outil de secours SafeMode minimal.
5. README_MODE_D_EMPLOI.txt            - Ce guide d'utilisation.

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
  link.download = 'SpaceSec_CyberDefense_Ultra_v3.5.zip';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
