export const CSHARP_EXTIRPATOR_CODE = `using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace SpaceSec.CyberDefense.Kernel
{
    /// <summary>
    /// SpaceSec Kernel File Extirpator & TrustedInstaller Annihilator (v3.0)
    /// Éradication complète de fichiers verrouillés au niveau OS / SYSTEM / TrustedInstaller.
    /// </summary>
    public static class KernelFileExtirpator
    {
        #region Win32 Constants & Enums

        [Flags]
        public enum MoveFileFlags : uint
        {
            MOVEFILE_REPLACE_EXISTING      = 0x00000001,
            MOVEFILE_COPY_ALLOWED          = 0x00000002,
            MOVEFILE_DELAY_UNTIL_REBOOT    = 0x00000004, // Exécution au démarrage par smss.exe / Session Manager
            MOVEFILE_WRITE_THROUGH         = 0x00000008,
            MOVEFILE_CREATE_HARDLINK       = 0x00000010,
            MOVEFILE_FAIL_IF_NOT_TRACKABLE = 0x00000020
        }

        private const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const int TOKEN_QUERY             = 0x0008;
        private const int SE_PRIVILEGE_ENABLED    = 0x00000002;

        public const string SE_DEBUG_NAME          = "SeDebugPrivilege";
        public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
        public const string SE_RESTORE_NAME        = "SeRestorePrivilege";
        public const string SE_BACKUP_NAME         = "SeBackupPrivilege";

        #endregion

        #region Native P/Invoke Declarations

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveFileEx(
            string lpExistingFileName,
            string lpNewFileName,
            MoveFileFlags dwFlags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            uint BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSuspendProcess(IntPtr processHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtResumeProcess(IntPtr processHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        // Restart Manager APIs (Détection et libération des verrous de fichiers)
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint pSessionHandle);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(
            uint pSessionHandle,
            uint nFiles,
            string[] rgsFileNames,
            uint nApplications,
            [In] RM_UNIQUE_PROCESS[] rgApplications,
            uint nServices,
            string[] rgsServiceNames);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(
            uint pSessionHandle,
            out uint pnProcInfoNeeded,
            ref uint pnProcInfo,
            [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
            out uint lpdwRebootReasons);

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privilege;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string strServiceShortName;
            public int ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bRestartable;
        }

        #endregion

        #region 1. Élévation des Privilèges NT du Processus

        /// <summary>
        /// Active les privilèges nécessaires au jeton du processus (SeDebug, SeTakeOwnership, SeRestore, SeBackup).
        /// Requis pour contourner les verrous DACL imposés par NT SERVICE\\TrustedInstaller.
        /// </summary>
        public static bool EnableProcessPrivileges()
        {
            string[] privileges = new[]
            {
                SE_DEBUG_NAME,
                SE_TAKE_OWNERSHIP_NAME,
                SE_RESTORE_NAME,
                SE_BACKUP_NAME
            };

            bool allSucceeded = true;
            foreach (var priv in privileges)
            {
                if (!SetPrivilege(priv, true))
                {
                    Console.WriteLine($"[AVERTISSEMENT] Impossible d'activer le privilège : {priv}");
                    allSucceeded = false;
                }
                else
                {
                    Console.WriteLine($"[OK] Privilège NT activé : {priv}");
                }
            }

            return allSucceeded;
        }

        private static bool SetPrivilege(string privilegeName, bool enable)
        {
            IntPtr hToken = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
                    return false;

                if (!LookupPrivilegeValue(null, privilegeName, out LUID luid))
                    return false;

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privilege = new LUID_AND_ATTRIBUTES
                    {
                        Luid = luid,
                        Attributes = enable ? (uint)SE_PRIVILEGE_ENABLED : 0
                    }
                };

                return AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
            finally
            {
                if (hToken != IntPtr.Zero)
                    CloseHandle(hToken);
            }
        }

        #endregion

        #region 2. Prise de Possession & FullControl (Bypass TrustedInstaller)

        /// <summary>
        /// Brise la propriété de TrustedInstaller, assigne le propriétaire au groupe Administrateurs
        /// et accorde les droits FullControl.
        /// </summary>
        public static bool TakeOwnershipAndGrantFullControl(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Fichier introuvable.", filePath);

            try
            {
                // Étape 1 : Réinitialiser les attributs système et lecture seule
                File.SetAttributes(filePath, FileAttributes.Normal);
                Console.WriteLine("[1/4] Attributs fichier réinitialisés à Normal.");

                // Étape 2 : Récupérer le SID du groupe BUILTIN\\\\Administrateurs (S-1-5-32-544)
                SecurityIdentifier adminGroupSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                NTAccount adminAccount = (NTAccount)adminGroupSid.Translate(typeof(NTAccount));

                // Étape 3 : Prendre la possession du fichier (Take Ownership)
                FileSecurity security = new FileSecurity(filePath, AccessControlSections.Owner);
                security.SetOwner(adminAccount);
                File.SetAccessControl(filePath, security);
                Console.WriteLine($"[2/4] Propriétaire transféré de TrustedInstaller vers : {adminAccount.Value}");

                // Étape 4 : Accorder le Contrôle Total (Full Control) aux Administrateurs
                FileSecurity accessSecurity = new FileSecurity(filePath, AccessControlSections.Access);
                FileSystemAccessRule fullControlRule = new FileSystemAccessRule(
                    adminAccount,
                    FileSystemRights.FullControl,
                    AccessControlType.Allow);

                accessSecurity.ResetAccessRule(fullControlRule);
                File.SetAccessControl(filePath, accessSecurity);
                Console.WriteLine("[3/4] Permissions FullControl appliquées avec succès.");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERREUR ACL] Échec de la modification des autorisations : {ex.Message}");
                // Fallback direct via takeown.exe et icacls.exe natifs en cas de filtre strict
                return ExecuteAclFallbackNative(filePath);
            }
        }

        private static bool ExecuteAclFallbackNative(string filePath)
        {
            try
            {
                Console.WriteLine("[FALLBACK] Exécution takeown.exe et icacls.exe...");
                RunProcess("takeown.exe", $"/f \\"{filePath}\\" /a");
                RunProcess("icacls.exe", $"\\"{filePath}\\" /grant *S-1-5-32-544:F /c /q");
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region 3. Neutralisation des Processus & Watchdogs

        /// <summary>
        /// Détecte les processus verrouillant le fichier via le Restart Manager,
        /// gèle leurs threads via NtSuspendProcess (pour empêcher la réanimation par watchdog),
        /// puis abat le processus.
        /// </summary>
        public static void UnlockAndKillLockingProcesses(string filePath)
        {
            List<Process> lockingProcesses = GetLockingProcesses(filePath);
            if (lockingProcesses.Count == 0)
            {
                Console.WriteLine("[OK] Aucun processus n'a de handle verrouillé sur le fichier.");
                return;
            }

            Console.WriteLine($"[ALERTE] {lockingProcesses.Count} processus verrouillent le fichier cible.");

            // Étape A : Geler tous les watchdogs simultanément en mémoire
            foreach (var proc in lockingProcesses)
            {
                try
                {
                    Console.WriteLine($"[SUSPEND] Appel NtSuspendProcess sur : {proc.ProcessName} (PID: {proc.Id})");
                    NtSuspendProcess(proc.Handle);
                }
                catch { }
            }

            // Étape B : Terminer de force les processus
            foreach (var proc in lockingProcesses)
            {
                try
                {
                    Console.WriteLine($"[KILL] Terminaison forcée de {proc.ProcessName} (PID: {proc.Id})");
                    proc.Kill();
                    proc.WaitForExit(1000);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[AVERTISSEMENT] Impossible de tuer PID {proc.Id} : {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Utilise l'API Windows Restart Manager pour identifier les processus bloquant le fichier.
        /// </summary>
        public static List<Process> GetLockingProcesses(string filePath)
        {
            var processes = new List<Process>();
            string key = Guid.NewGuid().ToString();

            if (RmStartSession(out uint sessionHandle, 0, key) != 0)
                return processes;

            try
            {
                string[] resources = new[] { filePath };
                if (RmRegisterResources(sessionHandle, 1, resources, 0, null, 0, null) != 0)
                    return processes;

                uint procInfoNeeded = 0;
                uint procInfo = 0;
                RM_PROCESS_INFO[] processInfo = new RM_PROCESS_INFO[1];

                int res = RmGetList(sessionHandle, out procInfoNeeded, ref procInfo, processInfo, out _);
                if (res == 234) // ERROR_MORE_DATA
                {
                    processInfo = new RM_PROCESS_INFO[procInfoNeeded];
                    procInfo = procInfoNeeded;
                    res = RmGetList(sessionHandle, out procInfoNeeded, ref procInfo, processInfo, out _);
                }

                if (res == 0)
                {
                    for (int i = 0; i < procInfo; i++)
                    {
                        try
                        {
                            processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                        }
                        catch { }
                    }
                }
            }
            finally
            {
                RmEndSession(sessionHandle);
            }

            return processes;
        }

        #endregion

        #region 4. Suppression Atomique Kernel (PendingFileRenameOperations)

        /// <summary>
        /// Écrase le binaire à 0 octet immédiatement pour le rendre inerte,
        /// puis l'enregistre via MoveFileEx dans PendingFileRenameOperations pour destruction au boot.
        /// </summary>
        public static bool ScheduleBootTimeDeletion(string filePath)
        {
            if (!File.Exists(filePath))
                return true;

            try
            {
                // Neutralisation immédiate : vider le contenu du fichier
                try
                {
                    File.WriteAllBytes(filePath, Array.Empty<byte>());
                    Console.WriteLine("[OK] Contenu du fichier tronqué à 0 octet (Payload neutralisé immédiatement).");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[INFO] Fichier actuellement locked en écriture : {ex.Message}");
                }

                // Inscription MoveFileEx avec le flag MOVEFILE_DELAY_UNTIL_REBOOT
                bool win32Success = MoveFileEx(filePath, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT);
                if (win32Success)
                {
                    Console.WriteLine("[SUCCÈS] MoveFileEx : Fichier inscrit pour suppression au reboot par le noyau Windows.");
                    return true;
                }

                int lastError = Marshal.GetLastWin32Error();
                Console.WriteLine($"[AVERTISSEMENT] MoveFileEx a retourné l'erreur Win32 : {lastError}. Bascule sur le fallback registre...");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERREUR MoveFileEx] : {ex.Message}");
            }

            // Fallback direct dans la ruche HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager
            return RegisterPendingFileRenameFallback(filePath);
        }

        private static bool RegisterPendingFileRenameFallback(string filePath)
        {
            try
            {
                const string sessionManagerKey = @"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
                const string valueName = "PendingFileRenameOperations";

                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(sessionManagerKey, writable: true))
                {
                    if (key == null) return false;

                    string nativeNtPath = @"\\??\\" + Path.GetFullPath(filePath);
                    object existingObj = key.GetValue(valueName);

                    List<string> entries = new List<string>();
                    if (existingObj is string[] existingArr)
                    {
                        entries.AddRange(existingArr);
                    }

                    // Dans Session Manager, une suppression est représentée par le chemin source suivi d'une chaîne vide
                    entries.Add(nativeNtPath);
                    entries.Add("");

                    key.SetValue(valueName, entries.ToArray(), RegistryValueKind.MultiString);
                    Console.WriteLine("[REGISTRE OK] Clé PendingFileRenameOperations mise à jour manuellement dans HKLM.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERREUR REGISTRE] : {ex.Message}");
                return false;
            }
        }

        #endregion

        #region 5. Protocole Complet d'Éradication Clé en Main

        /// <summary>
        /// Exécute l'intégralité du protocole d'éradication sur une cible protégée.
        /// </summary>
        public static bool EradicateTarget(string filePath)
        {
            Console.WriteLine("================================================================================");
            Console.WriteLine($"SPACESEC KERNEL EXTIRPATOR : Début du protocole sur : {filePath}");
            Console.WriteLine("================================================================================");

            // 1. Activer les privilèges SeDebug et SeTakeOwnership
            Console.WriteLine("[PHASE 1] Élévation des Privilèges NT...");
            EnableProcessPrivileges();

            // 2. Tuer les processus actifs et les watchdogs
            Console.WriteLine("\\n[PHASE 2] Recherche et neutralisation des verrous de processus...");
            UnlockAndKillLockingProcesses(filePath);

            // 3. Déposséder TrustedInstaller et accorder FullControl
            Console.WriteLine("\\n[PHASE 3] Dépossession ACL de TrustedInstaller & Octroi FullControl...");
            TakeOwnershipAndGrantFullControl(filePath);

            // 4. Tentative de suppression directe
            Console.WriteLine("\\n[PHASE 4] Tentative de suppression directe...");
            try
            {
                File.Delete(filePath);
                Console.WriteLine("[SUCCÈS MAJEUR] Fichier supprimé immédiatement du disque sans attendre le reboot !");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[INFO] Fichier maintenu par un handle système ({ex.Message}).");
            }

            // 5. Inscription PendingFileRenameOperations au boot
            Console.WriteLine("\\n[PHASE 5] Programmation de la suppression noyau au reboot...");
            bool scheduled = ScheduleBootTimeDeletion(filePath);

            if (scheduled)
            {
                Console.WriteLine("\\n================================================================================");
                Console.WriteLine("[RÉSULTAT] Binaire neutralisé et programmé pour destruction au prochain reboot !");
                Console.WriteLine("================================================================================");
                return true;
            }

            return false;
        }

        private static void RunProcess(string filename, string arguments)
        {
            using (Process p = new Process())
            {
                p.StartInfo.FileName = filename;
                p.StartInfo.Arguments = arguments;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.CreateNoWindow = true;
                p.Start();
                p.WaitForExit(3000);
            }
        }

        #endregion
    }
}
`;
