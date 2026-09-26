// build-icon.js — Génère desktop/assets/icon.ico (multi-résolution) depuis le SVG.
// Format ICO moderne : chaque entrée pointe vers un PNG embarqué.
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const SVG = path.join(__dirname, 'assets', 'icon.svg');
const OUT_ICO = path.join(__dirname, 'assets', 'icon.ico');
const SIZES = [256, 128, 64, 48, 32, 16];

async function build() {
  const svgBuf = fs.readFileSync(SVG);
  const pngs = [];
  for (const size of SIZES) {
    const png = await sharp(svgBuf, { density: 384 })
      .resize(size, size, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toBuffer();
    pngs.push({ size, buf: png });
    console.log(`  ${size}x${size}: ${png.length} bytes`);
  }

  // --- Assemblage du fichier ICO ---
  // Header ICONDIR (6 bytes) : reserved(2)=0, type(2)=1 (icon), count(2)=N
  const count = pngs.length;
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);   // reserved
  header.writeUInt16LE(1, 2);   // type = ICO
  header.writeUInt16LE(count, 4);

  // ICONDIRENTRY (16 bytes chacune) :
  //   width(1), height(1), colors(1)=0, reserved(1)=0, planes(2)=1, bpp(2)=32,
  //   size(4), offset(4)
  const entries = [];
  let offset = 6 + count * 16;
  for (const { size, buf } of pngs) {
    const entry = Buffer.alloc(16);
    entry.writeUInt8(size === 256 ? 0 : size, 0);  // width (256 stored as 0)
    entry.writeUInt8(size === 256 ? 0 : size, 1);  // height
    entry.writeUInt8(0, 2);                          // color count (0 = no palette)
    entry.writeUInt8(0, 3);                          // reserved
    entry.writeUInt16LE(1, 4);                       // color planes
    entry.writeUInt16LE(32, 6);                      // bits per pixel
    entry.writeUInt32LE(buf.length, 8);              // image size
    entry.writeUInt32LE(offset, 12);                 // image offset
    entries.push(entry);
    offset += buf.length;
  }

  const ico = Buffer.concat([header, ...entries, ...pngs.map((p) => p.buf)]);
  fs.writeFileSync(OUT_ICO, ico);
  console.log(`\n✓ ${OUT_ICO} écrit (${ico.length} bytes, ${count} résolutions)`);
}

build().catch((e) => { console.error(e); process.exit(1); });
