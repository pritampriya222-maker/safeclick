import React from 'react';
import { createRoot } from 'react-dom/client';
import { Options } from './Options';
import './options.css';

const container = document.getElementById('root');
if (!container) throw new Error('Root element not found');

createRoot(container).render(
  <React.StrictMode>
    <Options />
  </React.StrictMode>
);
