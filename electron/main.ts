import { app, BrowserWindow, shell, ipcMain } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';

process.env.IS_ELECTRON = 'true';

const isDev = process.env.NODE_ENV !== 'production' && !app.isPackaged;
const DEFAULT_PORT = 3000;

let mainWindow: BrowserWindow | null = null;
let serverProcess: any = null;

function waitForServer(url: string, timeoutMs = 15000): Promise<boolean> {
  const startTime = Date.now();
  return new Promise((resolve) => {
    const check = () => {
      const req = http.get(url, (res) => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 500) {
          resolve(true);
        } else {
          retry();
        }
      });
      req.on('error', () => retry());
      req.setTimeout(1000, () => {
        req.destroy();
        retry();
      });
    };

    const retry = () => {
      if (Date.now() - startTime > timeoutMs) {
        resolve(false);
      } else {
        setTimeout(check, 300);
      }
    };

    check();
  });
}

async function startBackendServer(): Promise<number> {
  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : DEFAULT_PORT;
  
  if (isDev) {
    // In dev, tsx / vite server is started concurrently
    return port;
  }

  try {
    // In production build, load the bundled backend server
    const serverModulePath = path.join(__dirname, 'server.cjs');
    let serverMod: any;
    try {
      // @ts-ignore
      serverMod = typeof require !== 'undefined' ? require(serverModulePath) : await import(serverModulePath);
    } catch (importErr) {
      serverMod = await import(serverModulePath);
    }

    const startServerFn = serverMod.startServer || serverMod.default?.startServer || (typeof serverMod === 'function' ? serverMod : null);
    if (typeof startServerFn === 'function') {
      await startServerFn(port);
      console.log(`[Electron Main] Embedded Space Security server started on port ${port}`);
    }
  } catch (err) {
    console.error('[Electron Main] Failed to dynamically start server module:', err);
  }

  return port;
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1100,
    minHeight: 720,
    backgroundColor: '#020617', // Dark slate cyber background
    show: false,
    autoHideMenuBar: true,
    title: 'Space Security - CyberDefense Suite & Kernel Extirpator',
    icon: path.join(__dirname, '../build/icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  // Open target links in default external browser rather than inside the app window
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http:') || url.startsWith('https:')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  const port = await startBackendServer();
  const targetUrl = `http://localhost:${port}`;

  console.log(`[Electron Main] Waiting for local server at ${targetUrl}...`);
  const isReady = await waitForServer(targetUrl, 12000);
  
  if (isReady) {
    await mainWindow.loadURL(targetUrl);
  } else {
    console.warn(`[Electron Main] Server wait timed out, attempting direct load...`);
    await mainWindow.loadURL(targetUrl).catch((err) => {
      console.error('[Electron Main] Failed to load URL:', err);
    });
  }

  mainWindow.once('ready-to-show', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Single instance lock to prevent duplicate windows
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(createWindow);

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
      app.quit();
    }
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
}
