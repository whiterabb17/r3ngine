import React from 'react';
import './api/axiosConfig';
import ReactDOM from 'react-dom';
import * as ReactDOMClient from 'react-dom/client';
import * as MaterialUI from '@mui/material';
import * as MaterialUIStyles from '@mui/material/styles';
// Explicit registry — only icons used in the app/plugins are bundled.
// Add new entries here when a plugin needs an additional icon.
import {
  AccountTree,
  Check,
  Close,
  Delete,
  Download,
  Extension,
  FilterList,
  GppBad,
  GppMaybe,
  Inventory,
  Refresh,
  Settings,
  Store,
  Upload,
  VerifiedUser,
} from '@mui/icons-material';

const MaterialUIIcons = {
  AccountTree,
  Check,
  Close,
  Delete,
  Download,
  Extension,
  FilterList,
  GppBad,
  GppMaybe,
  Inventory,
  Refresh,
  Settings,
  Store,
  Upload,
  VerifiedUser,
};
import * as LucideReact from 'lucide-react';
import cytoscape from 'cytoscape';
import App from './App';
import './index.css';

// Globals that dynamically loaded plugin bundles read instead of bundling their own copies.
declare global {
  interface Window {
    React: typeof React;
    ReactDOM: typeof ReactDOM & typeof ReactDOMClient;
    MaterialUI: typeof MaterialUI;
    MaterialUIStyles: typeof MaterialUIStyles;
    MaterialUIIcons: typeof MaterialUIIcons;
    LucideReact: typeof LucideReact;
    Cytoscape: typeof cytoscape;
  }
}

// Bind React and dependencies to window for dynamic plugins loading
window.React = React;
window.ReactDOM = { ...ReactDOM, ...ReactDOMClient };
window.MaterialUI = MaterialUI;
window.MaterialUIStyles = MaterialUIStyles;
window.MaterialUIIcons = MaterialUIIcons;
window.LucideReact = LucideReact;
window.Cytoscape = cytoscape;



import { reloadOnceForStaleBuild } from './utils/staleBuild';
import '@fontsource/orbitron/index.css';
import '@fontsource/inter/index.css';
import '@fontsource/bangers/index.css';

// A chunk of the previous build failed to load after a redeploy: load the new build.
window.addEventListener('vite:preloadError', (event) => {
  if (reloadOnceForStaleBuild()) event.preventDefault();
});

ReactDOMClient.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
