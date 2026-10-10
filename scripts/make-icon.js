'use strict';

// Генератор иконки приложения: build/icon.ico (256x256, PNG внутри ICO).
//写 без внешних зависимостей и графических утилит — рисуем в буфер RGBA,
// кодируем PNG вручную (zlib есть в Node) и заворачиваем в ICO-контейнер.
//
// Запуск: npm run make:icon

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const SIZE = 256;

// ---------------------------------------------------------------- рисование

function mix(a, b, t) {
  return [
    Math.round(a[0] + (b[0] - a[0]) * t),
    Math.round(a[1] + (b[1] - a[1]) * t),
    Math.round(a[2] + (b[2] - a[2]) * t),
  ];
}

// Полуширина щита на высоте y (y в [-1, 1]).
function shieldHalfWidth(y) {
  const top = -1;
  const shoulder = 0.15;
  if (y < top) return 0;
  if (y <= shoulder) {
    // Верхняя часть — почти прямая со скруглением у самой макушки.
    const t = (y - top) / (shoulder - top);
    return 0.82 * Math.min(1, Math.sqrt(Math.max(0, 1 - Math.pow(1 - t * 1.25, 6))));
  }
  // Низ — плавное сведение в острие.
  const t = (y - shoulder) / (1 - shoulder);
  return 0.82 * Math.sqrt(Math.max(0, 1 - t * t));
}

// Расстояние до отрезка — для «галочки».
function distToSegment(px, py, x1, y1, x2, y2) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const lengthSq = dx * dx + dy * dy;
  let t = lengthSq === 0 ? 0 : ((px - x1) * dx + (py - y1) * dy) / lengthSq;
  t = Math.max(0, Math.min(1, t));
  const cx = x1 + t * dx;
  const cy = y1 + t * dy;
  return Math.hypot(px - cx, py - cy);
}

function renderRgba() {
  const pixels = Buffer.alloc(SIZE * SIZE * 4, 0);

  const outerTop = [0x4c, 0x8d, 0xf0];
  const outerBottom = [0x16, 0x39, 0x78];
  const innerTop = [0x2f, 0x6f, 0xd0];
  const innerBottom = [0x11, 0x2c, 0x5e];

  // Сглаживание: считаем покрытие по сетке 3x3 внутри пикселя.
  const SUB = 3;

  for (let py = 0; py < SIZE; py += 1) {
    for (let px = 0; px < SIZE; px += 1) {
      let shieldHits = 0;
      let innerHits = 0;
      let markHits = 0;

      for (let sy = 0; sy < SUB; sy += 1) {
        for (let sx = 0; sx < SUB; sx += 1) {
          const fx = px + (sx + 0.5) / SUB;
          const fy = py + (sy + 0.5) / SUB;
          const x = (fx / SIZE) * 2 - 1;
          const y = (fy / SIZE) * 2 - 1;

          const hw = shieldHalfWidth(y * 1.04);
          if (Math.abs(x) <= hw) {
            shieldHits += 1;

            const hwInner = shieldHalfWidth(y * 1.04 / 0.86) * 0.86;
            if (Math.abs(x) <= hwInner && y * 1.04 <= 0.86) {
              innerHits += 1;
            }
          }

          // Галочка внутри щита.
          const d = Math.min(
            distToSegment(x, y, -0.34, -0.02, -0.08, 0.26),
            distToSegment(x, y, -0.08, 0.26, 0.38, -0.32)
          );
          if (d <= 0.085) markHits += 1;
        }
      }

      const total = SUB * SUB;
      const shieldA = shieldHits / total;
      if (shieldA === 0) continue;

      const t = py / SIZE;
      let color = mix(outerTop, outerBottom, t);

      const innerA = innerHits / total;
      if (innerA > 0) {
        color = mix(color, mix(innerTop, innerBottom, t), innerA);
      }

      const markA = markHits / total;
      if (markA > 0) {
        color = mix(color, [0xff, 0xff, 0xff], markA);
      }

      const offset = (py * SIZE + px) * 4;
      pixels[offset] = color[0];
      pixels[offset + 1] = color[1];
      pixels[offset + 2] = color[2];
      pixels[offset + 3] = Math.round(shieldA * 255);
    }
  }

  return pixels;
}

// ------------------------------------------------------------- кодирование

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
})();

function crc32(buffer) {
  let c = 0xffffffff;
  for (let i = 0; i < buffer.length; i += 1) {
    c = CRC_TABLE[(c ^ buffer[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeAndData = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typeAndData), 0);
  return Buffer.concat([length, typeAndData, crc]);
}

function encodePng(rgba) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(SIZE, 0);
  ihdr.writeUInt32BE(SIZE, 4);
  ihdr[8] = 8; // бит на канал
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  // Каждая строка с фильтром 0.
  const raw = Buffer.alloc(SIZE * (SIZE * 4 + 1));
  for (let y = 0; y < SIZE; y += 1) {
    raw[y * (SIZE * 4 + 1)] = 0;
    rgba.copy(raw, y * (SIZE * 4 + 1) + 1, y * SIZE * 4, (y + 1) * SIZE * 4);
  }

  return Buffer.concat([
    signature,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function encodeIco(png) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type: icon
  header.writeUInt16LE(1, 4); // количество изображений

  const entry = Buffer.alloc(16);
  entry[0] = 0; // ширина 256 кодируется нулём
  entry[1] = 0; // высота 256
  entry[2] = 0; // палитра не используется
  entry[3] = 0;
  entry.writeUInt16LE(1, 4); // плоскости
  entry.writeUInt16LE(32, 6); // бит на пиксель
  entry.writeUInt32LE(png.length, 8);
  entry.writeUInt32LE(header.length + entry.length, 12);

  return Buffer.concat([header, entry, png]);
}

// ------------------------------------------------------------------- запуск

const buildDir = path.join(__dirname, '..', 'build');
fs.mkdirSync(buildDir, { recursive: true });

const png = encodePng(renderRgba());
fs.writeFileSync(path.join(buildDir, 'icon.png'), png);
fs.writeFileSync(path.join(buildDir, 'icon.ico'), encodeIco(png));

console.log(`Иконка создана: build/icon.ico (${SIZE}x${SIZE}), build/icon.png`);
