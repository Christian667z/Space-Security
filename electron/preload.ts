import { contextBridge } from 'electron';

// Expose safe desktop info to the React frontend
contextBridge.exposeInMainWorld('desktopApp', {
  isElectron: true,
  platform: process.platform,
  version: '1.0.0',
});
