(function () {
  'use strict';

  const STORAGE_KEY_ADJ = 'jra_rating_custom_adj_v1';
  const STORAGE_KEY_PWD = 'jra_rating_saved_pwd_v1';
  const CURRENT_YEAR = 2026;

  // =========================================================================
  // 純粋JavaScriptによるSHA-256およびChaCha20復号エンジン (file:// でも動作)
  // =========================================================================
  const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function sha256Bytes(msgBytes) {
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    const len = msgBytes.length;
    const bitLen = len * 8;
    const padLen = ((len + 9 + 63) & ~63);
    const padded = new Uint8Array(padLen);
    padded.set(msgBytes);
    padded[len] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padLen - 4, bitLen >>> 0, false);
    view.setUint32(padLen - 8, Math.floor(bitLen / 4294967296), false);

    const w = new Uint32Array(64);
    for (let offset = 0; offset < padLen; offset += 64) {
      for (let i = 0; i < 16; i++) {
        w[i] = view.getUint32(offset + i * 4, false);
      }
      for (let i = 16; i < 64; i++) {
        const v15 = w[i - 15];
        const s0 = ((v15 >>> 7) | (v15 << 25)) ^ ((v15 >>> 18) | (v15 << 14)) ^ (v15 >>> 3);
        const v2 = w[i - 2];
        const s1 = ((v2 >>> 17) | (v2 << 15)) ^ ((v2 >>> 19) | (v2 << 13)) ^ (v2 >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }

      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;

        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    outView.setUint32(0, h0, false); outView.setUint32(4, h1, false);
    outView.setUint32(8, h2, false); outView.setUint32(12, h3, false);
    outView.setUint32(16, h4, false); outView.setUint32(20, h5, false);
    outView.setUint32(24, h6, false); outView.setUint32(28, h7, false);
    return out;
  }

  function concatBytes(a, b, c) {
    const total = a.length + b.length + (c ? c.length : 0);
    const res = new Uint8Array(total);
    res.set(a, 0);
    res.set(b, a.length);
    if (c) res.set(c, a.length + b.length);
    return res;
  }

  function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      s += bytes[i].toString(16).padStart(2, '0');
    }
    return s;
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const len = bin.length;
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function chacha20QuarterRound(x, a, b, c, d) {
    x[a] = (x[a] + x[b]) >>> 0; x[d] ^= x[a]; x[d] = (x[d] << 16) | (x[d] >>> 16);
    x[c] = (x[c] + x[d]) >>> 0; x[b] ^= x[c]; x[b] = (x[b] << 12) | (x[b] >>> 20);
    x[a] = (x[a] + x[b]) >>> 0; x[d] ^= x[a]; x[d] = (x[d] << 8) | (x[d] >>> 24);
    x[c] = (x[c] + x[d]) >>> 0; x[b] ^= x[c]; x[b] = (x[b] << 7) | (x[b] >>> 25);
  }

  function chacha20Decrypt(keyBytes, salt12Bytes, cipherBytes) {
    const keyView = new DataView(keyBytes.buffer, keyBytes.byteOffset, 32);
    const saltView = new DataView(salt12Bytes.buffer, salt12Bytes.byteOffset, 12);

    const state = new Uint32Array(16);
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (let i = 0; i < 8; i++) {
      state[4 + i] = keyView.getUint32(i * 4, true);
    }
    state[12] = 0; // 初期カウンタ = 0
    state[13] = saltView.getUint32(0, true);
    state[14] = saltView.getUint32(4, true);
    state[15] = saltView.getUint32(8, true);

    const out = new Uint8Array(cipherBytes.length);
    const working = new Uint32Array(16);
    const keystreamBytes = new Uint8Array(working.buffer);

    const len = cipherBytes.length;
    for (let pos = 0; pos < len; pos += 64) {
      working.set(state);
      for (let r = 0; r < 10; r++) {
        chacha20QuarterRound(working, 0, 4, 8, 12);
        chacha20QuarterRound(working, 1, 5, 9, 13);
        chacha20QuarterRound(working, 2, 6, 10, 14);
        chacha20QuarterRound(working, 3, 7, 11, 15);
        chacha20QuarterRound(working, 0, 5, 10, 15);
        chacha20QuarterRound(working, 1, 6, 11, 12);
        chacha20QuarterRound(working, 2, 7, 8, 13);
        chacha20QuarterRound(working, 3, 4, 9, 14);
      }
      for (let i = 0; i < 16; i++) {
        working[i] = (working[i] + state[i]) >>> 0;
      }
      const blockLen = Math.min(64, len - pos);
      for (let i = 0; i < blockLen; i++) {
        out[pos + i] = cipherBytes[pos + i] ^ keystreamBytes[i];
      }
      state[12] = (state[12] + 1) >>> 0;
    }
    return out;
  }

  function tryDecryptWithPassword(password) {
    const encObj = window.JRA_ENCRYPTED_DATA;
    if (!encObj) return null;

    const encoder = new TextEncoder();
    const pwdBytes = encoder.encode(password);
    const saltBytes = base64ToBytes(encObj.salt);

    let k = sha256Bytes(concatBytes(pwdBytes, saltBytes));
    for (let i = 0; i < 999; i++) {
      k = sha256Bytes(concatBytes(k, pwdBytes, saltBytes));
    }

    const verifyBytes = sha256Bytes(concatBytes(k, encoder.encode('VERIFY')));
    const verifyHex = bytesToHex(verifyBytes).slice(0, 16);
    if (verifyHex !== encObj.verify) {
      return null;
    }

    const cipherBytes = base64ToBytes(encObj.payload);
    const plainBytes = chacha20Decrypt(k, saltBytes, cipherBytes);
    const decoder = new TextDecoder('utf-8');
    const jsonStr = decoder.decode(plainBytes);
    return JSON.parse(jsonStr);
  }

  // =========================================================================
  // アプリケーション本体
  // =========================================================================
  let HORSES = {};
  let RECORDS = [];
  let customAdjustments = {};
  let currentMode = 'horse';
  let currentPage = 1;
  let pageSize = 100;
  let currentRows = [];
  let appInitialized = false;

  const elSearch = document.getElementById('fSearch');
  const elStatus = document.getElementById('fStatus');
  const elBirthYear = document.getElementById('fBirthYear');
  const elRunAge = document.getElementById('fRunAge');
  const elSurface = document.getElementById('fSurface');
  const elCategory = document.getElementById('fCategory');
  const elDistance = document.getElementById('fDistance');
  const elSex = document.getElementById('fSex');
  const elGrade = document.getElementById('fGrade');
  const elYearFrom = document.getElementById('fYearFrom');
  const elYearTo = document.getElementById('fYearTo');
  const elRank = document.getElementById('fRank');
  const elVenue = document.getElementById('fVenue');
  const elRatingSource = document.getElementById('fRatingSource');
  const elPageSize = document.getElementById('pageSizeSelect');
  const elThead = document.getElementById('rankingThead');
  const elTbody = document.getElementById('rankingTbody');
  const elPager = document.getElementById('pagerBar');

  function startAppWithData(dataObj) {
    HORSES = dataObj.horses || {};
    RECORDS = dataObj.records || [];

    try {
      const saved = localStorage.getItem(STORAGE_KEY_ADJ);
      if (saved) customAdjustments = JSON.parse(saved);
    } catch (e) {
      console.warn(e);
    }

    RECORDS.forEach((r) => {
      if (customAdjustments[r.id] !== undefined && customAdjustments[r.id] !== null && customAdjustments[r.id] !== '') {
        r.adj = parseFloat(customAdjustments[r.id]);
      }
    });

    document.getElementById('authScreen').classList.add('hidden');
    document.getElementById('appRoot').classList.remove('hidden');

    if (!appInitialized) {
      initFilterOptions();
      bindEvents();
      appInitialized = true;
    }
    updateView();
  }

  function initFilterOptions() {
    const birthYears = new Set();
    const distances = new Set();
    const years = new Set();

    Object.values(HORSES).forEach((h) => {
      if (h.by) birthYears.add(h.by);
    });
    RECORDS.forEach((r) => {
      if (r.dist) distances.add(r.dist);
      if (r.y) years.add(r.y);
    });

    const sortedBY = Array.from(birthYears).sort((a, b) => b - a);
    sortedBY.forEach((by) => {
      const ageIn2026 = CURRENT_YEAR - by;
      const opt = document.createElement('option');
      opt.value = String(by);
      opt.textContent = `${by}年産（${String(by).slice(2)}世代・現${ageIn2026}歳）`;
      elBirthYear.appendChild(opt);
    });

    const sortedDist = Array.from(distances).sort((a, b) => a - b);
    sortedDist.forEach((d) => {
      const opt = document.createElement('option');
      opt.value = String(d);
      opt.textContent = `${d}m`;
      elDistance.appendChild(opt);
    });

    const sortedYears = Array.from(years).sort((a, b) => a - b);
    const minYear = sortedYears[0] || 2017;
    const maxYear = sortedYears[sortedYears.length - 1] || 2026;

    sortedYears.forEach((y) => {
      const opt1 = document.createElement('option');
      opt1.value = String(y);
      opt1.textContent = `${y}年`;
      if (y === minYear) opt1.selected = true;
      elYearFrom.appendChild(opt1);

      const opt2 = document.createElement('option');
      opt2.value = String(y);
      opt2.textContent = `${y}年`;
      if (y === maxYear) opt2.selected = true;
      elYearTo.appendChild(opt2);
    });
  }

  function getEffectiveRating(rec, sourceMode) {
    if (sourceMode === 'official') return rec.rt;
    if (rec.adj !== null && rec.adj !== undefined && !isNaN(rec.adj)) {
      return Number(rec.adj);
    }
    return rec.rt;
  }

  function getFilteredRecords() {
    const q = elSearch.value.trim().toUpperCase();
    const st = elStatus.value;
    const by = elBirthYear.value;
    const runAge = elRunAge.value;
    const surf = elSurface.value;
    const cat = elCategory.value;
    const dist = elDistance.value;
    const sex = elSex.value;
    const grade = elGrade.value;
    const yFrom = parseInt(elYearFrom.value, 10) || 2017;
    const yTo = parseInt(elYearTo.value, 10) || 2026;
    const rk = elRank.value;
    const venue = elVenue.value;
    const rSource = elRatingSource.value;

    return RECORDS.filter((r) => {
      const h = HORSES[r.hid] || {};

      if (rSource === 'only_adjusted' && (r.adj === null || r.adj === undefined || isNaN(r.adj))) {
        return false;
      }
      if (r.y < yFrom || r.y > yTo) return false;

      if (st === 'active_jra' && h.st !== '現役') return false;
      if (st === 'active_all' && h.st !== '現役' && h.st !== '現役(地方)') return false;
      if (st === 'active_nar' && h.st !== '現役(地方)') return false;
      if (st === 'retired' && h.st !== '引退') return false;

      if (by !== 'all' && String(h.by) !== by) return false;

      if (runAge !== 'all') {
        if (runAge === '2' && r.age !== 2) return false;
        if (runAge === '3' && r.age !== 3) return false;
        if (runAge === '3_under' && r.age > 3) return false;
        if (runAge === '4_over' && r.age < 4) return false;
        if (runAge === '4' && r.age !== 4) return false;
        if (runAge === '5' && r.age !== 5) return false;
        if (runAge === '6_over' && r.age < 6) return false;
      }

      if (surf !== 'all' && r.s !== surf) return false;

      if (cat !== 'all') {
        if (cat === 'ILE') {
          if (!['I', 'L', 'E'].includes(r.cat)) return false;
        } else if (cat === 'SM') {
          if (!['S', 'M'].includes(r.cat)) return false;
        } else if (r.cat !== cat) {
          return false;
        }
      }

      if (dist !== 'all' && String(r.dist) !== dist) return false;

      if (sex !== 'all') {
        if (sex === 'male_gelding') {
          if (h.sex !== '牡' && h.sex !== 'セ') return false;
        } else if (h.sex !== sex) {
          return false;
        }
      }

      if (grade !== 'all') {
        if (grade === 'G1' && r.g !== 'GⅠ' && r.g !== 'JpnⅠ') return false;
        if (grade === 'G1_G2' && !['GⅠ', 'JpnⅠ', 'GⅡ'].includes(r.g)) return false;
        if (grade === 'graded' && !['GⅠ', 'JpnⅠ', 'GⅡ', 'GⅢ'].includes(r.g)) return false;
        if (grade === 'non_graded' && ['GⅠ', 'JpnⅠ', 'GⅡ', 'GⅢ'].includes(r.g)) return false;
      }

      if (rk !== 'all') {
        if (rk === '1' && r.rk !== 1) return false;
        if (rk === '2_under' && r.rk > 2) return false;
        if (rk === '3_under' && r.rk > 3) return false;
        if (rk === '2_over' && r.rk < 2) return false;
      }

      if (venue !== 'all' && r.v !== venue) return false;

      if (q) {
        const target = `${r.hn} ${r.rn} ${h.sire || ''} ${h.dam || ''} ${r.memo || ''}`.toUpperCase();
        if (!target.includes(q)) return false;
      }

      return true;
    });
  }

  function formatRatingPill(val, isAdjusted) {
    let cls = 'rt-normal';
    if (val >= 125) cls = 'rt-125';
    else if (val >= 120) cls = 'rt-120';
    else if (val >= 115) cls = 'rt-115';
    const mark = isAdjusted ? ' *' : '';
    return `<span class="rating-pill ${cls}">${val}${mark}</span>`;
  }

  function formatStatusBadge(st) {
    if (st === '現役') return '<span class="status-badge st-active">現役</span>';
    if (st === '現役(地方)') return '<span class="status-badge st-nar">地方現役</span>';
    return '<span class="status-badge st-retired">引退</span>';
  }

  function formatGradeBadge(g) {
    if (g === 'GⅠ' || g === 'JpnⅠ') return `<span class="grade-badge g-G1">${g}</span>`;
    if (g === 'GⅡ') return `<span class="grade-badge g-G2">${g}</span>`;
    if (g === 'GⅢ') return `<span class="grade-badge g-G3">${g}</span>`;
    if (g === 'L') return `<span class="grade-badge g-L">L</span>`;
    return `<span class="grade-badge g-OP">OP</span>`;
  }

  function formatCourseBadge(s, dist, cat) {
    const cls = s === '芝' ? 'course-turf' : 'course-dirt';
    const label = s === '芝' ? '芝' : 'ダ';
    return `<span class="course-badge ${cls}">${label}${dist}m</span><span class="cat-badge">${cat}</span>`;
  }

  function formatRankBadge(rank) {
    const cls = rank === 1 ? 'rank-1' : rank === 2 ? 'rank-2' : rank === 3 ? 'rank-3' : '';
    return `<span class="rank-num ${cls}">${rank}</span>`;
  }

  function updateView() {
    const filtered = getFilteredRecords();
    const rSource = elRatingSource.value;

    const horseBestMap = new Map();
    filtered.forEach((r) => {
      const eff = getEffectiveRating(r, rSource);
      const existing = horseBestMap.get(r.hid);
      if (!existing) {
        horseBestMap.set(r.hid, {
          hid: r.hid,
          bestRec: r,
          bestRating: eff,
          count: 1,
          cats: new Set([r.cat]),
        });
      } else {
        existing.count += 1;
        existing.cats.add(r.cat);
        if (
          eff > existing.bestRating ||
          (eff === existing.bestRating && r.rk < existing.bestRec.rk) ||
          (eff === existing.bestRating && r.rk === existing.bestRec.rk && r.ym > existing.bestRec.ym)
        ) {
          existing.bestRating = eff;
          existing.bestRec = r;
        }
      }
    });

    const horseList = Array.from(horseBestMap.values()).sort((a, b) => {
      if (b.bestRating !== a.bestRating) return b.bestRating - a.bestRating;
      if (b.bestRec.rt !== a.bestRec.rt) return b.bestRec.rt - a.bestRec.rt;
      return b.count - a.count;
    });

    document.getElementById('statUniqueHorses').textContent = `${horseList.length.toLocaleString()} 頭`;
    document.getElementById('statTotalRecords').textContent = `${filtered.length.toLocaleString()} 件`;

    if (horseList.length > 0) {
      document.getElementById('statMaxRating').textContent = horseList[0].bestRating.toFixed(0);
      const topN = horseList.slice(0, Math.min(10, horseList.length));
      const avg = topN.reduce((acc, x) => acc + x.bestRating, 0) / topN.length;
      document.getElementById('statTop10Avg').textContent = avg.toFixed(1);
    } else {
      document.getElementById('statMaxRating').textContent = '-';
      document.getElementById('statTop10Avg').textContent = '-';
    }

    if (currentMode === 'horse') {
      let currentRank = 1;
      horseList.forEach((item, idx) => {
        if (idx > 0 && item.bestRating < horseList[idx - 1].bestRating) {
          currentRank = idx + 1;
        }
        item.rank = currentRank;
      });
      currentRows = horseList;
    } else if (currentMode === 'record') {
      const recList = filtered
        .map((r) => ({
          rec: r,
          effRating: getEffectiveRating(r, rSource),
        }))
        .sort((a, b) => {
          if (b.effRating !== a.effRating) return b.effRating - a.effRating;
          if (a.rec.rk !== b.rec.rk) return a.rec.rk - b.rec.rk;
          return b.rec.ym.localeCompare(a.rec.ym);
        });

      let currentRank = 1;
      recList.forEach((item, idx) => {
        if (idx > 0 && item.effRating < recList[idx - 1].effRating) {
          currentRank = idx + 1;
        }
        item.rank = currentRank;
      });
      currentRows = recList;
    } else if (currentMode === 'race') {
      const raceMap = new Map();
      filtered.forEach((r) => {
        const eff = getEffectiveRating(r, rSource);
        const existing = raceMap.get(r.rid);
        if (!existing) {
          raceMap.set(r.rid, {
            rid: r.rid,
            ym: r.ym,
            d: r.d,
            v: r.v,
            rn: r.rn,
            g: r.g,
            s: r.s,
            dist: r.dist,
            cat: r.cat,
            rr: r.rr,
            topHorse: r.hn,
            topHid: r.hid,
            topRating: eff,
            count: 1,
          });
        } else {
          existing.count += 1;
          if (eff > existing.topRating) {
            existing.topRating = eff;
            existing.topHorse = r.hn;
            existing.topHid = r.hid;
          }
        }
      });

      const raceList = Array.from(raceMap.values()).sort((a, b) => {
        const rrA = a.rr || 0;
        const rrB = b.rr || 0;
        if (rrB !== rrA) return rrB - rrA;
        return b.topRating - a.topRating;
      });

      let currentRank = 1;
      raceList.forEach((item, idx) => {
        const prev = idx > 0 ? raceList[idx - 1] : null;
        if (prev && (item.rr || 0) < (prev.rr || 0)) {
          currentRank = idx + 1;
        }
        item.rank = currentRank;
      });
      currentRows = raceList;
    }

    renderTable();
  }

  function renderTable() {
    const total = currentRows.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;

    const startIdx = (currentPage - 1) * pageSize;
    const pageItems = currentRows.slice(startIdx, startIdx + pageSize);
    const rSource = elRatingSource.value;

    if (currentMode === 'horse') {
      elThead.innerHTML = `
        <tr>
          <th>順位</th>
          <th>馬名 / ステータス</th>
          <th>世代・性</th>
          <th>最高R</th>
          <th>最高R達成レース</th>
          <th>コース・区分</th>
          <th>着順(当時年齢)</th>
          <th>該当数</th>
        </tr>
      `;
      elTbody.innerHTML = pageItems
        .map((item) => {
          const r = item.bestRec;
          const h = HORSES[item.hid] || {};
          const isAdj = rSource !== 'official' && r.adj !== null && r.adj !== undefined && !isNaN(r.adj);
          const genText = h.by ? `${String(h.by).slice(2)}世代(${h.by})` : '-';
          return `
            <tr>
              <td>${formatRankBadge(item.rank)}</td>
              <td>
                <a class="horse-link" data-hid="${item.hid}">${r.hn}</a>
                ${formatStatusBadge(h.st)}
              </td>
              <td>${genText}・${h.sex || '-'}</td>
              <td>${formatRatingPill(item.bestRating, isAdj)}</td>
              <td>
                ${formatGradeBadge(r.g)}
                <a class="race-link" data-rid="${r.rid}">${r.rn}</a>
                <small style="color:#64748b">(${r.ym} ${r.v})</small>
              </td>
              <td>${formatCourseBadge(r.s, r.dist, r.cat)}</td>
              <td>${r.rk}着 <small style="color:#64748b">(${r.age}歳時)</small></td>
              <td><strong>${item.count}</strong>回 <small style="color:#64748b">[${Array.from(item.cats).join('・')}]</small></td>
            </tr>
          `;
        })
        .join('');
    } else if (currentMode === 'record') {
      elThead.innerHTML = `
        <tr>
          <th>順位</th>
          <th>馬名 / ステータス</th>
          <th>評価R</th>
          <th>公式R</th>
          <th>自分の補正</th>
          <th>年月・開催</th>
          <th>レース名</th>
          <th>コース・区分</th>
          <th>着順(年齢)</th>
        </tr>
      `;
      elTbody.innerHTML = pageItems
        .map((item) => {
          const r = item.rec;
          const h = HORSES[r.hid] || {};
          const hasAdj = r.adj !== null && r.adj !== undefined && !isNaN(r.adj);
          const isAdj = rSource !== 'official' && hasAdj;
          return `
            <tr>
              <td>${formatRankBadge(item.rank)}</td>
              <td>
                <a class="horse-link" data-hid="${r.hid}">${r.hn}</a>
                ${formatStatusBadge(h.st)}
              </td>
              <td>${formatRatingPill(item.effRating, isAdj)}</td>
              <td>${r.rt}</td>
              <td>
                <input type="number" step="0.5" class="adj-input ${hasAdj ? 'has-val' : ''}"
                  data-rec-id="${r.id}" value="${hasAdj ? r.adj : ''}" placeholder="-">
              </td>
              <td>${r.ym} <small style="color:#64748b">${r.d}(${r.v})</small></td>
              <td>
                ${formatGradeBadge(r.g)}
                <a class="race-link" data-rid="${r.rid}">${r.rn}</a>
              </td>
              <td>${formatCourseBadge(r.s, r.dist, r.cat)}</td>
              <td>${r.rk}着 <small style="color:#64748b">(${h.sex || ''}${r.age}歳)</small></td>
            </tr>
          `;
        })
        .join('');
    } else if (currentMode === 'race') {
      elThead.innerHTML = `
        <tr>
          <th>順位</th>
          <th>年月・開催日</th>
          <th>レース名</th>
          <th>コース・区分</th>
          <th>レースR (R・R)</th>
          <th>レース内最高R馬</th>
          <th>掲載頭数</th>
        </tr>
      `;
      elTbody.innerHTML = pageItems
        .map((item) => {
          const rrText = item.rr ? item.rr.toFixed(2) : '-';
          return `
            <tr>
              <td>${formatRankBadge(item.rank)}</td>
              <td>${item.ym} ${item.d} (${item.v})</td>
              <td>
                ${formatGradeBadge(item.g)}
                <a class="race-link" data-rid="${item.rid}">${item.rn}</a>
              </td>
              <td>${formatCourseBadge(item.s, item.dist, item.cat)}</td>
              <td><strong style="font-size:1.02rem;color:#1d4ed8">${rrText}</strong></td>
              <td>
                <a class="horse-link" data-hid="${item.topHid}">${item.topHorse}</a>
                (${formatRatingPill(item.topRating, false)})
              </td>
              <td>${item.count}頭</td>
            </tr>
          `;
        })
        .join('');
    }

    if (pageItems.length === 0) {
      elTbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:32px;color:#64748b">条件に一致するデータがありません。フィルタ条件を変更してください。</td></tr>`;
    }

    renderPager(total, totalPages);
  }

  function renderPager(total, totalPages) {
    const start = total === 0 ? 0 : (currentPage - 1) * pageSize + 1;
    const end = Math.min(total, currentPage * pageSize);

    elPager.innerHTML = `
      <div>全 <strong>${total.toLocaleString()}</strong> 件中 ${start.toLocaleString()}〜${end.toLocaleString()} 件を表示</div>
      <div class="pager-btns">
        <button type="button" class="pager-btn" data-page="1" ${currentPage <= 1 ? 'disabled' : ''}>≪ 先頭</button>
        <button type="button" class="pager-btn" data-page="${currentPage - 1}" ${currentPage <= 1 ? 'disabled' : ''}>＜ 前へ</button>
        <span style="padding:6px 10px;font-size:0.85rem;font-weight:700">${currentPage} / ${totalPages} ページ</span>
        <button type="button" class="pager-btn" data-page="${currentPage + 1}" ${currentPage >= totalPages ? 'disabled' : ''}>次へ ＞</button>
        <button type="button" class="pager-btn" data-page="${totalPages}" ${currentPage >= totalPages ? 'disabled' : ''}>末尾 ≫</button>
      </div>
    `;
  }

  function openHorseModal(hid) {
    const h = HORSES[hid] || {};
    const horseRecs = RECORDS.filter((r) => r.hid === hid).sort((a, b) => b.ym.localeCompare(a.ym));
    if (horseRecs.length === 0) return;

    const rSource = elRatingSource.value;
    const maxRt = Math.max(...horseRecs.map((r) => getEffectiveRating(r, rSource)));

    const catBests = {};
    ['S', 'M', 'I', 'L', 'E'].forEach((c) => {
      const sub = horseRecs.filter((r) => r.cat === c);
      if (sub.length > 0) {
        catBests[c] = Math.max(...sub.map((r) => getEffectiveRating(r, rSource)));
      }
    });

    const pedigreeText = h.sire ? `父：${h.sire} ／ 母：${h.dam || '-'}` : '';
    const genAge = h.by ? `${h.by}年産（現${CURRENT_YEAR - h.by}歳）` : '';

    document.getElementById('horseModalTitleArea').innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <h3 style="font-size:1.25rem">${h.name || horseRecs[0].hn}</h3>
        ${formatStatusBadge(h.st)}
        <span style="font-size:0.85rem;color:#cbd5e1">${genAge} ${h.sex || ''}</span>
      </div>
      ${pedigreeText ? `<div style="font-size:0.8rem;color:#94a3b8;margin-top:2px">${pedigreeText}</div>` : ''}
      <a class="ext-link" href="https://db.netkeiba.com/horse/${hid}/" target="_blank" rel="noopener">
        🔗 netkeiba 馬プロフィールを開く (ID: ${hid}) ↗
      </a>
    `;

    const catBoxesHtml = ['S', 'M', 'I', 'L', 'E']
      .map((c) => {
        const val = catBests[c];
        return `
          <div class="cat-summary-item">
            <div style="font-size:0.75rem;color:#64748b;font-weight:700">区分 ${c}</div>
            <div style="font-size:1.15rem;font-weight:800;margin-top:2px;color:${val ? '#0f172a' : '#cbd5e1'}">
              ${val || '-'}
            </div>
          </div>
        `;
      })
      .join('');

    const rowsHtml = horseRecs
      .map((r) => {
        const hasAdj = r.adj !== null && r.adj !== undefined && !isNaN(r.adj);
        return `
          <tr>
            <td>${r.ym} ${r.d}</td>
            <td>${r.v}</td>
            <td>
              ${formatGradeBadge(r.g)}
              <a class="race-link" data-rid="${r.rid}">${r.rn}</a>
            </td>
            <td>${formatCourseBadge(r.s, r.dist, r.cat)}</td>
            <td><strong>${r.rk}着</strong> (${r.age}歳)</td>
            <td>${formatRatingPill(r.rt, false)}</td>
            <td>
              <input type="number" step="0.5" class="adj-input ${hasAdj ? 'has-val' : ''}"
                data-rec-id="${r.id}" value="${hasAdj ? r.adj : ''}" placeholder="-">
            </td>
          </tr>
        `;
      })
      .join('');

    document.getElementById('horseModalBody').innerHTML = `
      <div class="cat-summary-box">
        <div class="cat-summary-item" style="background:#fef2f2;border-color:#fecaca">
          <div style="font-size:0.75rem;color:#991b1b;font-weight:700">キャリア最高R</div>
          <div style="font-size:1.25rem;font-weight:800;color:#dc2626;margin-top:2px">${maxRt}</div>
        </div>
        ${catBoxesHtml}
      </div>
      <h4 style="margin-bottom:8px;font-size:0.92rem">📋 レーティング獲得履歴（全 ${horseRecs.length} 戦）</h4>
      <div class="table-responsive">
        <table class="ranking-table">
          <thead>
            <tr>
              <th>実施日</th>
              <th>場</th>
              <th>レース名</th>
              <th>コース</th>
              <th>着順</th>
              <th>公式R</th>
              <th>自分の補正</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    `;

    document.getElementById('horseModal').classList.remove('hidden');
  }

  function openRaceModal(rid) {
    const raceRecs = RECORDS.filter((r) => r.rid === rid).sort((a, b) => a.rk - b.rk);
    if (raceRecs.length === 0) return;
    const r0 = raceRecs[0];

    document.getElementById('raceModalTitleArea').innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        ${formatGradeBadge(r0.g)}
        <h3 style="font-size:1.2rem">${r0.rn}</h3>
        <span style="font-size:0.85rem;color:#cbd5e1">${r0.ym} ${r0.d}（${r0.v}）</span>
      </div>
      <div style="font-size:0.82rem;color:#cbd5e1;margin-top:4px">
        コース：${r0.s}${r0.dist}m（区分：${r0.cat}） ／ レースレーティング(R・R)：<strong>${r0.rr || '-'}</strong>
      </div>
      <a class="ext-link" href="https://race.netkeiba.com/race/result.html?race_id=${rid}" target="_blank" rel="noopener">
        🔗 netkeiba レース結果ページを開く (レースID: ${rid}) ↗
      </a>
    `;

    const rowsHtml = raceRecs
      .map((r) => {
        const h = HORSES[r.hid] || {};
        const hasAdj = r.adj !== null && r.adj !== undefined && !isNaN(r.adj);
        return `
          <tr>
            <td><strong>${r.rk}着</strong></td>
            <td>
              <a class="horse-link" data-hid="${r.hid}">${r.hn}</a>
              ${formatStatusBadge(h.st)}
            </td>
            <td>${h.by || '-'}年 (${h.sex || ''}${r.age}歳)</td>
            <td>${formatRatingPill(r.rt, false)}</td>
            <td>
              <input type="number" step="0.5" class="adj-input ${hasAdj ? 'has-val' : ''}"
                data-rec-id="${r.id}" value="${hasAdj ? r.adj : ''}" placeholder="-">
            </td>
            <td style="font-size:0.78rem;color:#64748b">${r.memo || ''}</td>
          </tr>
        `;
      })
      .join('');

    document.getElementById('raceModalBody').innerHTML = `
      <div class="table-responsive">
        <table class="ranking-table">
          <thead>
            <tr>
              <th>着順</th>
              <th>馬名</th>
              <th>生年(当時性齢)</th>
              <th>公式R</th>
              <th>自分の補正</th>
              <th>メモ</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    `;

    document.getElementById('raceModal').classList.remove('hidden');
  }

  function applyPreset(presetName) {
    resetAllFilterSelects();
    switch (presetName) {
      case 'active_jra':
        elStatus.value = 'active_jra';
        break;
      case 'gen_2023':
        elBirthYear.value = '2023';
        break;
      case 'gen_2022':
        elBirthYear.value = '2022';
        break;
      case 'gen_2021':
        elBirthYear.value = '2021';
        break;
      case 'gen_2024':
        elBirthYear.value = '2024';
        break;
      case 'active_sprint':
        elStatus.value = 'active_jra';
        elCategory.value = 'S';
        break;
      case 'active_mile':
        elStatus.value = 'active_jra';
        elCategory.value = 'M';
        break;
      case 'active_middle':
        elStatus.value = 'active_jra';
        elCategory.value = 'ILE';
        break;
      case 'active_dirt':
        elStatus.value = 'active_jra';
        elSurface.value = 'ダート';
        break;
      case 'active_mare':
        elStatus.value = 'active_jra';
        elSex.value = '牝';
        break;
      case 'year_2026':
        elYearFrom.value = '2026';
        elYearTo.value = '2026';
        break;
      case 'age_2yo':
        elRunAge.value = '2';
        break;
      case 'age_3yo':
        elRunAge.value = '3';
        break;
      default:
        break;
    }
    currentPage = 1;
    updateView();
  }

  function resetAllFilterSelects() {
    elSearch.value = '';
    elStatus.value = 'all';
    elBirthYear.value = 'all';
    elRunAge.value = 'all';
    elSurface.value = 'all';
    elCategory.value = 'all';
    elDistance.value = 'all';
    elSex.value = 'all';
    elGrade.value = 'all';
    elYearFrom.value = '2017';
    elYearTo.value = '2026';
    elRank.value = 'all';
    elVenue.value = 'all';
    elRatingSource.value = 'adjusted';
  }

  function exportCurrentCsv() {
    if (currentRows.length === 0) {
      alert('出力するデータがありません。');
      return;
    }
    const lines = [];
    if (currentMode === 'horse') {
      lines.push(['順位', 'netkeiba馬ID', '馬名', 'ステータス', '生年', '性別', '最高レーティング', '達成年月', 'レース名', 'グレード', '芝ダート', '距離(m)', '距離区分', '着順', '該当記録数'].join(','));
      currentRows.forEach((item) => {
        const r = item.bestRec;
        const h = HORSES[item.hid] || {};
        lines.push([
          item.rank,
          item.hid,
          `"${r.hn}"`,
          h.st || '',
          h.by || '',
          h.sex || '',
          item.bestRating,
          r.ym,
          `"${r.rn}"`,
          r.g,
          r.s,
          r.dist,
          r.cat,
          r.rk,
          item.count,
        ].join(','));
      });
    } else if (currentMode === 'record') {
      lines.push(['順位', '年月', '実施日', '実施場', 'レース名', 'グレード', '芝ダート', '距離(m)', '距離区分', '着順', '馬名', '公式レーティング', '自分の補正', '評価レーティング', 'netkeibaレースID', 'netkeiba馬ID'].join(','));
      currentRows.forEach((item) => {
        const r = item.rec;
        lines.push([
          item.rank,
          r.ym,
          r.d,
          r.v,
          `"${r.rn}"`,
          r.g,
          r.s,
          r.dist,
          r.cat,
          r.rk,
          `"${r.hn}"`,
          r.rt,
          r.adj !== null && r.adj !== undefined ? r.adj : '',
          item.effRating,
          r.rid,
          r.hid,
        ].join(','));
      });
    } else {
      lines.push(['順位', '年月', '実施日', '実施場', 'レース名', 'グレード', '芝ダート', '距離(m)', '距離区分', 'レースレーティング', '最高R馬名', '最高R', 'netkeibaレースID'].join(','));
      currentRows.forEach((item) => {
        lines.push([
          item.rank,
          item.ym,
          item.d,
          item.v,
          `"${item.rn}"`,
          item.g,
          item.s,
          item.dist,
          item.cat,
          item.rr || '',
          `"${item.topHorse}"`,
          item.topRating,
          item.rid,
        ].join(','));
      });
    }

    const bom = new Uint8Array([0xef, 0xbb, 0xbf]);
    const blob = new Blob([bom, lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `JRAレーティング_${currentMode}_ランキング.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function bindEvents() {
    const filterEls = [
      elStatus, elBirthYear, elRunAge, elSurface, elCategory,
      elDistance, elSex, elGrade, elYearFrom, elYearTo,
      elRank, elVenue, elRatingSource,
    ];
    filterEls.forEach((el) => {
      el.addEventListener('change', () => {
        document.querySelectorAll('.preset-chip').forEach((c) => c.classList.remove('active'));
        currentPage = 1;
        updateView();
      });
    });

    elSearch.addEventListener('input', () => {
      currentPage = 1;
      updateView();
    });

    document.getElementById('btnResetFilters').addEventListener('click', () => {
      document.querySelectorAll('.preset-chip').forEach((c) => c.classList.remove('active'));
      document.querySelector('.preset-chip[data-preset="all"]').classList.add('active');
      resetAllFilterSelects();
      currentPage = 1;
      updateView();
    });

    document.querySelectorAll('.preset-chip').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.preset-chip').forEach((c) => c.classList.remove('active'));
        btn.classList.add('active');
        applyPreset(btn.dataset.preset);
      });
    });

    document.querySelectorAll('.mode-tab').forEach((tab) => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.mode-tab').forEach((t) => t.classList.remove('active'));
        tab.classList.add('active');
        currentMode = tab.dataset.mode;
        currentPage = 1;
        updateView();
      });
    });

    elPageSize.addEventListener('change', () => {
      pageSize = parseInt(elPageSize.value, 10) || 100;
      currentPage = 1;
      renderTable();
    });

    elPager.addEventListener('click', (e) => {
      const btn = e.target.closest('.pager-btn');
      if (!btn || btn.disabled) return;
      currentPage = parseInt(btn.dataset.page, 10);
      renderTable();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    document.body.addEventListener('click', (e) => {
      const horseLink = e.target.closest('.horse-link');
      if (horseLink) {
        e.preventDefault();
        openHorseModal(horseLink.dataset.hid);
        return;
      }
      const raceLink = e.target.closest('.race-link');
      if (raceLink) {
        e.preventDefault();
        openRaceModal(raceLink.dataset.rid);
        return;
      }
    });

    document.body.addEventListener('change', (e) => {
      const input = e.target.closest('.adj-input');
      if (!input) return;
      const recId = parseInt(input.dataset.recId, 10);
      const valStr = input.value.trim();
      const targetRec = RECORDS.find((r) => r.id === recId);
      if (!targetRec) return;

      if (valStr === '') {
        targetRec.adj = null;
        delete customAdjustments[recId];
        input.classList.remove('has-val');
      } else {
        const num = parseFloat(valStr);
        if (!isNaN(num)) {
          targetRec.adj = num;
          customAdjustments[recId] = num;
          input.classList.add('has-val');
        }
      }
      try {
        localStorage.setItem(STORAGE_KEY_ADJ, JSON.stringify(customAdjustments));
      } catch (err) {
        console.warn(err);
      }
      updateView();
    });

    document.getElementById('btnCloseHorseModal').addEventListener('click', () => {
      document.getElementById('horseModal').classList.add('hidden');
    });
    document.getElementById('btnCloseRaceModal').addEventListener('click', () => {
      document.getElementById('raceModal').classList.add('hidden');
    });
    document.querySelectorAll('.modal-backdrop').forEach((bd) => {
      bd.addEventListener('click', (e) => {
        if (e.target === bd) bd.classList.add('hidden');
      });
    });

    document.getElementById('btnToggleFilterMobile').addEventListener('click', () => {
      const panel = document.getElementById('filterPanel');
      panel.classList.toggle('hidden');
    });

    document.getElementById('btnExportCsv').addEventListener('click', exportCurrentCsv);

    // 手動ロックボタン
    document.getElementById('btnLockApp').addEventListener('click', () => {
      try {
        localStorage.removeItem(STORAGE_KEY_PWD);
      } catch (e) {}
      document.getElementById('appRoot').classList.add('hidden');
      document.getElementById('authPasswordInput').value = '';
      document.getElementById('authErrorMsg').classList.add('hidden');
      document.getElementById('authScreen').classList.remove('hidden');
    });
  }

  // 認証画面初期化
  function initAuth() {
    const authForm = document.getElementById('authForm');
    const pwdInput = document.getElementById('authPasswordInput');
    const rememberCheck = document.getElementById('authRememberCheck');
    const errBox = document.getElementById('authErrorMsg');

    // 保存済みパスワードがあれば自動復号を試行
    try {
      const savedPwd = localStorage.getItem(STORAGE_KEY_PWD);
      if (savedPwd) {
        const dec = tryDecryptWithPassword(savedPwd);
        if (dec) {
          startAppWithData(dec);
          return;
        }
      }
    } catch (e) {
      console.warn(e);
    }

    authForm.addEventListener('submit', (e) => {
      e.preventDefault();
      errBox.classList.add('hidden');
      const pwd = pwdInput.value.trim();
      if (!pwd) return;

      try {
        const dec = tryDecryptWithPassword(pwd);
        if (!dec) {
          errBox.classList.remove('hidden');
          return;
        }
        if (rememberCheck.checked) {
          try {
            localStorage.setItem(STORAGE_KEY_PWD, pwd);
          } catch (err) {}
        } else {
          try {
            localStorage.removeItem(STORAGE_KEY_PWD);
          } catch (err) {}
        }
        startAppWithData(dec);
      } catch (err) {
        console.error(err);
        errBox.classList.remove('hidden');
      }
    });
  }

  initAuth();
})();
