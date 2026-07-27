# SafeClick Icons

These are placeholder SVG icons. Chrome MV3 accepts PNG icons as declared in manifest.json.

## Converting SVG → PNG for production
Run one of:
```bash
# Using Inkscape (recommended, free):
inkscape --export-type=png --export-width=128 icon128.svg -o icon128.png

# Using ImageMagick:
magick icon128.svg -resize 128x128 icon128.png

# Using sharp (Node.js):
npm install sharp
node -e "const sharp=require('sharp'); [16,32,48,128].forEach(s => sharp('icon'+s+'.svg').resize(s).png().toFile('icon'+s+'.png'));"
```

For Phase 1 development, rename the SVG files to .png — Chrome will accept SVGs
when loaded as an unpacked extension (it reads the file regardless of extension
for dev purposes). For store submission, use proper PNGs.
