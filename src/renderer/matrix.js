'use strict';

// Фон экрана проверки в стиле «Матрицы»: падающий код, из которого
// периодически проступает Нео (карта яркости кадра — neo-map.js,
// собирается скриптом design-mockups/neo_prep.py).
//
// MatrixScene.mount(container) кладёт canvas первым ребёнком контейнера
// и возвращает функцию остановки (снимает canvas и цикл анимации).

(function () {
  const CELL = 16;
  const CHARS = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ0123456789Z:.=*+<>'.split('');
  const randChar = () => CHARS[(Math.random() * CHARS.length) | 0];

  // Цикл 24 с: 0–6 Нео нет; 6–9.5 проступает из падающих струй; 9.5–18 стоит
  // (по нему бегут волны кода); 18–21 осыпается вниз. Сдвиг START — чтобы
  // при открытии экрана он появился почти сразу.
  const CYCLE = 24;
  const START = 5;

  let neo = null;
  function neoMap() {
    if (neo || !window.NEO_MAP) return neo;
    const { nx, ny, nx0, ny0, data } = window.NEO_MAP;
    const bin = atob(data);
    const lum = new Float32Array(nx * ny);
    for (let i = 0; i < lum.length; i += 1) lum[i] = bin.charCodeAt(i) / 255;
    neo = { nx, ny, nx0, ny0, lum };
    return neo;
  }

  function mount(container) {
    const map = neoMap();
    const canvas = document.createElement('canvas');
    canvas.className = 'matrix-rain';
    container.prepend(canvas);
    const ctx = canvas.getContext('2d');

    let W = 0;
    let H = 0;
    let cols = 0;
    let rows = 0;
    let drops = [];
    let grid = [];
    function resize() {
      W = canvas.width = canvas.clientWidth;
      H = canvas.height = canvas.clientHeight;
      cols = Math.ceil(W / CELL);
      rows = Math.ceil(H / CELL);
      drops = Array.from({ length: cols }, () => Math.random() * rows);
      grid = Array.from({ length: cols * rows }, randChar);
    }

    const NX = map ? map.nx : 0;
    const NY = map ? map.ny : 0;
    const offs = Array.from({ length: NX }, () => Math.random() * 18);
    const aGrid = Array.from({ length: NX * NY }, randChar);
    const waves = Array.from({ length: NX }, () => ({ y: Math.random() * NY, v: 0.25 + Math.random() * 0.35 }));

    function neoState(t) {
      const c = t % CYCLE;
      if (!map || c < 6 || c > 21.3) return null;
      return { build: c < 9.5 ? (c - 6) / 3.5 : 2, fall: c > 18 ? (c - 18) / 3 : -1 };
    }

    function neoBox() {
      const cell = Math.max(5, Math.floor(Math.min((W * 0.8) / map.nx0, (H - 150) / map.ny0)));
      return { cell, x: (W - cell * NX) / 2, y: 6, w: cell * NX };
    }

    function drawNeo(s, box) {
      const AC = box.cell;
      ctx.font = `bold ${AC + 1}px Consolas, monospace`;
      const span = NY + 20;
      for (let x = 0; x < NX; x += 1) {
        const head = s.build * span - offs[x];
        const tail = s.fall < 0 ? -1 : s.fall * span - offs[x];
        const w = waves[x];
        w.y = (w.y + w.v) % (NY + 30);
        for (let y = 0; y < NY; y += 1) {
          if (y > head || y < tail) continue;
          const edge = Math.abs(y - head) < 1.5 || (tail >= 0 && Math.abs(y - tail) < 1.5);
          let L = map.lum[y * NX + x];
          // Волна кода: яркий «гребень» бежит по колонке сверху вниз, как в фильме.
          const dw = w.y - y;
          if (dw >= 0 && dw < 8) L = Math.min(1, L * (1 + 0.9 * (1 - dw / 8)) + (dw < 1 ? 0.25 * L : 0));
          if (L < 0.05 && !edge) continue;
          if (Math.random() < 0.04) aGrid[y * NX + x] = randChar();
          const px = box.x + x * AC;
          const py = box.y + y * AC;
          ctx.fillStyle = '#050906';
          ctx.fillRect(px, py, AC, AC);
          const v = Math.min(1, Math.pow(L, 0.65) * 1.45);
          if (edge) ctx.fillStyle = 'rgba(225,255,235,0.95)';
          else if (v > 0.86) ctx.fillStyle = `rgb(${(170 + 70 * v) | 0},255,${(190 + 50 * v) | 0})`;
          else ctx.fillStyle = `rgb(${(20 + 60 * v) | 0},${(70 + 185 * v) | 0},${(45 + 95 * v) | 0})`;
          ctx.fillText(aGrid[y * NX + x], px, py);
        }
      }
    }

    function frame(t) {
      if (canvas.clientWidth !== W || canvas.clientHeight !== H) resize();
      ctx.fillStyle = 'rgba(10,15,11,0.14)';
      ctx.fillRect(0, 0, W, H);
      ctx.font = `${CELL - 2}px Consolas, monospace`;
      ctx.textBaseline = 'top';

      const s = neoState(t);
      const box = s ? neoBox() : null;
      for (let x = 0; x < cols; x += 1) {
        const y = Math.floor(drops[x]);
        // Под Нео струи приглушаем, чтобы он читался.
        const a = box && x * CELL > box.x - 20 && x * CELL < box.x + box.w + 20 ? 0.35 : 1;
        ctx.fillStyle = `rgba(200,255,215,${a})`;
        ctx.fillText(grid[(x * rows + y) % grid.length], x * CELL, y * CELL);
        drops[x] += 0.35 + (x % 5) * 0.08;
        if (drops[x] * CELL > H && Math.random() > 0.975) drops[x] = 0;
      }
      if (s) drawNeo(s, box);
    }

    let raf = 0;
    const startedAt = performance.now();
    resize();
    (function loop(now) {
      frame((now - startedAt) / 1000 + START);
      raf = requestAnimationFrame(loop);
    })(startedAt);

    return function stop() {
      cancelAnimationFrame(raf);
      canvas.remove();
    };
  }

  window.MatrixScene = { mount };
})();
