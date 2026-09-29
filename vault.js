/* Ôn thi HK1 · 2C — password gate for the published copy (built by publish/build.js).
   All study content (data, app code, audio) is AES-256-GCM encrypted with a key derived from the class password
   (PBKDF2-SHA256). Decryption happens only in the browser; the password is never sent anywhere.
   The class link …/#k=<base64url key> (printed by build.js) opens the site without typing the password;
   a URL fragment is never sent to the server. */
'use strict';
(function () {
  const C = window.VAULT, KEY = 'onthi2c.vk', MAX_TRACKS = 6;
  const $ = s => document.querySelector(s);
  const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64e = u => btoa(String.fromCharCode.apply(null, u));
  const saved = {
    get() { try { return JSON.parse(sessionStorage.getItem(KEY) || localStorage.getItem(KEY) || 'null'); } catch (e) { return null; } },
    set(v, remember) { saved.del(); try { (remember ? localStorage : sessionStorage).setItem(KEY, JSON.stringify(v)); } catch (e) { } },
    del() { try { localStorage.removeItem(KEY); sessionStorage.removeItem(KEY); } catch (e) { } },
  };
  let aes = null, appP = null;

  async function fetchBuf(url, onProgress) {
    const r = await fetch(url);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    if (!onProgress || !r.body || !r.body.getReader) return r.arrayBuffer();
    const total = +r.headers.get('content-length') || 0, rd = r.body.getReader(), parts = [];
    let got = 0;
    for (;;) {
      const { done, value } = await rd.read();
      if (done) break;
      parts.push(value); got += value.length; onProgress(got, total);
    }
    const out = new Uint8Array(got);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out.buffer;
  }
  const decrypt = (key, buf) => { const u = new Uint8Array(buf); return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.subarray(0, 12) }, key, u.subarray(12)); };
  const appBuf = () => appP || (appP = fetchBuf(C.app).catch(e => { appP = null; throw e; }));

  async function deriveKey(pass) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass.normalize('NFC').trim()), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64d(C.salt), iterations: C.iter }, base, 256));
  }

  // Decrypted [[file, code], ...] of the app, or null if the key is wrong. Network errors are thrown.
  async function openWith(raw) {
    const buf = await appBuf();
    let key, plain;
    try { key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']); plain = await decrypt(key, buf); } catch (e) { return null; }
    aes = key;
    return JSON.parse(new TextDecoder().decode(plain));
  }

  function boot(files) {
    for (const [name, code] of files) {
      const s = document.createElement('script');
      s.textContent = code + '\n//# sourceURL=' + name;
      document.body.appendChild(s);
    }
    const acts = $('.top-actions'), lock = document.createElement('button');
    lock.className = 'icon-btn'; lock.type = 'button'; lock.textContent = '🔒';
    lock.title = 'Khoá trang trên máy này (lần sau phải nhập lại mật khẩu)';
    lock.onclick = () => {
      if (confirm('Khoá trang trên máy này? Lần sau sẽ phải nhập lại mật khẩu (tiến độ ôn tập vẫn được giữ).')) { saved.del(); location.reload(); }
    };
    acts.appendChild(lock); acts.classList.remove('hidden');
    try { App.start(); } catch (e) { console.error(e); fail('Lỗi khởi động trang: ' + e.message); }
  }

  function fail(msg) {
    $('#main').innerHTML = '<div class="card lock"><div class="lock-ico">⚠️</div><p class="lock-err"></p>' +
      '<button class="btn pri" type="button" onclick="location.reload()">↻ Thử lại</button></div>';
    $('.lock-err').textContent = msg;
  }

  function screen(msg) {
    document.title = 'Ôn thi HK1 · 2C – Nhập mật khẩu';
    $('#main').innerHTML = '<div class="card lock"><div class="lock-ico">🔒</div><h1>Ôn thi HK1 · Lớp 2C</h1>' +
      '<p class="muted">Trang ôn tập dành riêng cho lớp 2C VB2 Ngôn ngữ Anh.<br>Bấm link lớp gửi trong nhóm, hoặc nhập mật khẩu lớp (mỗi máy chỉ cần 1 lần).</p>' +
      '<form id="vf"><div class="lock-row"><input id="vp" type="password" placeholder="Mật khẩu lớp" autocomplete="current-password" autocapitalize="none" autocorrect="off" spellcheck="false" required>' +
      '<button id="ve" class="btn" type="button" title="Hiện / ẩn mật khẩu">👁</button></div>' +
      '<label class="small lock-rem"><input id="vr" type="checkbox" checked> Ghi nhớ trên máy này</label>' +
      '<button id="vb" class="btn pri" type="submit">Vào ôn thi →</button><div id="vm" class="fb bad" role="alert"></div></form></div>';
    const inp = $('#vp'), btn = $('#vb'), m = $('#vm');
    if (msg) m.textContent = msg;
    $('#ve').onclick = () => { inp.type = inp.type === 'password' ? 'text' : 'password'; inp.focus(); };
    $('#vf').onsubmit = async e => {
      e.preventDefault();
      btn.disabled = true; m.className = 'fb muted'; m.textContent = '⏳ Đang mở khoá…';
      try {
        const raw = await deriveKey(inp.value), files = await openWith(raw);
        if (!files) { m.className = 'fb bad'; m.textContent = '✗ Sai mật khẩu, bạn kiểm tra lại nhé.'; btn.disabled = false; inp.select(); return; }
        saved.set({ s: C.salt, k: b64e(raw) }, $('#vr').checked);
        boot(files);
      } catch (err) {
        m.className = 'fb bad'; m.textContent = '⚠️ Không tải được trang (' + err.message + '). Kiểm tra mạng rồi thử lại.'; btn.disabled = false;
      }
    };
    setTimeout(() => inp.focus(), 50);
  }

  async function start() {
    if (!C || !window.crypto || !crypto.subtle || !window.TextDecoder || !window.fetch) {
      return fail('Trình duyệt này chưa hỗ trợ. Hãy mở trang bằng Chrome, Edge hoặc Safari bản mới (địa chỉ phải bắt đầu bằng https://).');
    }
    appBuf().catch(() => { }); // start downloading while the password is being typed
    // Anything a chat app appends after the 43-character key is ignored; the key is removed from the address bar.
    const isLink = /^#k=/.test(location.hash), link = /^#k=([\w-]{43})/.exec(location.hash);
    if (isLink) history.replaceState(null, '', location.pathname + location.search);
    const badLink = 'Link này đã cũ hoặc bị thiếu ký tự – bạn lấy link mới trong nhóm lớp, hoặc nhập mật khẩu lớp.';
    const s = saved.get(), tries = [];
    if (link) tries.push({ k: link[1].replace(/-/g, '+').replace(/_/g, '/'), link: true });
    if (s && s.s === C.salt && s.k) tries.push({ k: s.k });
    if (!tries.length) { if (s) saved.del(); return screen(isLink ? badLink : ''); }
    $('#main').innerHTML = '<p class="muted" style="padding:2rem">⏳ Đang mở…</p>';
    for (const t of tries) {
      let raw, files;
      try { raw = b64d(t.k); } catch (e) { continue; }
      try { files = await openWith(raw); } catch (e) { return fail('Không tải được trang (' + e.message + '). Kiểm tra mạng rồi thử lại.'); }
      if (files) { if (t.link) saved.set({ s: C.salt, k: b64e(raw) }, true); return boot(files); }
    }
    saved.del();
    screen(isLink ? badLink : 'Mật khẩu của trang đã được đổi – bạn nhập mật khẩu mới nhé.');
  }

  // Encrypted textbook audio: download + decrypt on demand into blob: URLs (a few recent tracks are kept in memory).
  const tracks = new Map();
  function track(src) {
    let t = tracks.get(src);
    if (t) { tracks.delete(src); tracks.set(src, t); return t; }
    t = { subs: new Set() };
    t.p = (async () => {
      const v = C.files[src];
      if (!v) throw new Error('không có file ' + src);
      const buf = await fetchBuf(src + '.enc?v=' + v, (got, total) => t.subs.forEach(f => f(got, total)));
      return URL.createObjectURL(new Blob([await decrypt(aes, buf)], { type: 'audio/mpeg' }));
    })();
    t.p.catch(() => { if (tracks.get(src) === t) tracks.delete(src); });
    tracks.set(src, t);
    for (const [k, old] of tracks) {
      if (tracks.size <= MAX_TRACKS) break;
      tracks.delete(k); old.p.then(u => URL.revokeObjectURL(u), () => { });
    }
    return t;
  }
  function media(a, src) {
    const t = track(src), st = document.createElement('span');
    st.className = 'vst small muted'; st.textContent = '⏳ Đang tải audio…';
    const show = setTimeout(() => { if (a.isConnected && !a.getAttribute('src')) a.after(st); }, 0);
    const prog = (got, total) => { st.textContent = '⏳ Đang tải audio… ' + (total ? Math.min(99, Math.round(got * 100 / total)) + '%' : (got / 1048576).toFixed(1) + ' MB'); };
    t.subs.add(prog);
    return t.p.then(u => { t.subs.delete(prog); clearTimeout(show); st.remove(); a.src = u; },
      e => {
        t.subs.delete(prog); st.className = 'vst small fb bad';
        st.textContent = '⚠️ Không tải được audio (' + e.message + ') – kiểm tra mạng rồi mở lại trang.'; throw e;
      });
  }

  window.Vault = { media };
  start();
})();
