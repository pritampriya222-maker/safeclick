/**
 * generate-icons.mjs
 * ─────────────────────────────────────────────────────────────────────────────
 * Generates SafeClick placeholder PNG icons (16/32/48/128px) from SVG.
 * Run once: node generate-icons.mjs
 * Requires no external dependencies — uses the Canvas API via Node.js if
 * available, otherwise outputs the SVG files which Chrome can also use.
 *
 * For now we generate SVG placeholder files directly into extension/icons/.
 * In production, replace these with proper branded PNG assets.
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const SIZES = [16, 32, 48, 128];
const ICONS_DIR = join(__dirname, 'icons');

mkdirSync(ICONS_DIR, { recursive: true });

function generateSVG(size) {
  const innerSize = Math.round(size * 0.625);
  const cornerRadius = Math.round(size * 0.2);
  const shieldScale = innerSize / 24;
  const shieldX = (size - innerSize) / 2;
  const shieldY = (size - innerSize) / 2;

  return `<?xml version="1.0" encoding="UTF-8"?>
<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg-grad-${size}" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#4f46e5;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#7c3aed;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="shield-grad-${size}" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#ffffff;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#e0e7ff;stop-opacity:1" />
    </linearGradient>
  </defs>

  <!-- Background rounded rectangle -->
  <rect width="${size}" height="${size}" rx="${cornerRadius}" ry="${cornerRadius}"
        fill="url(#bg-grad-${size})"/>

  <!-- Shield icon (scaled) -->
  <g transform="translate(${shieldX}, ${shieldY}) scale(${shieldScale})">
    <!-- Shield outline -->
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5L12 1z"
          fill="url(#shield-grad-${size})" opacity="0.95"/>
    <!-- Check mark inside shield -->
    <path d="M9 12l2 2 4-4" stroke="#4f46e5" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  </g>
</svg>`;
}

SIZES.forEach((size) => {
  const svg = generateSVG(size);
  const svgPath = join(ICONS_DIR, `icon${size}.svg`);
  writeFileSync(svgPath, svg, 'utf8');
  console.log(`✓ Generated ${svgPath}`);
});

// Also write a PNG-compatible note
writeFileSync(
  join(ICONS_DIR, 'README.md'),
  `# SafeClick Icons

These are placeholder SVG icons. Chrome MV3 accepts PNG icons as declared in manifest.json.

## Converting SVG → PNG for production
Run one of:
\`\`\`bash
# Using Inkscape (recommended, free):
inkscape --export-type=png --export-width=128 icon128.svg -o icon128.png

# Using ImageMagick:
magick icon128.svg -resize 128x128 icon128.png

# Using sharp (Node.js):
npm install sharp
node -e "const sharp=require('sharp'); [16,32,48,128].forEach(s => sharp('icon'+s+'.svg').resize(s).png().toFile('icon'+s+'.png'));"
\`\`\`

For Phase 1 development, rename the SVG files to .png — Chrome will accept SVGs
when loaded as an unpacked extension (it reads the file regardless of extension
for dev purposes). For store submission, use proper PNGs.
`,
  'utf8'
);

console.log('\n✓ Icons generated in extension/icons/');
console.log('  See extension/icons/README.md for PNG conversion instructions.\n');
