import { contextBridge, ipcRenderer } from 'electron';

// Expose safe desktop info and secure IPC token to the React frontend
contextBridge.exposeInMainWorld('desktopApp', {
  isElectron: true,
  platform: process.platform,
  version: '1.0.0',
  getAuthToken: () => ipcRenderer.invoke('get-auth-token'),
});
