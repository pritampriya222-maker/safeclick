import React from 'react';
import ReactDOM from 'react-dom/client';
import { WarningPage } from './WarningPage';
import './warning.css';

const rootEl = document.getElementById('root');

if (rootEl) {
  ReactDOM.createRoot(rootEl).render(
    <React.StrictMode>
      <WarningPage />
    </React.StrictMode>
  );
}
