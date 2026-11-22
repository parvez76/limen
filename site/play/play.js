// Parvez playground. No third-party code: the compiler is parvez.wasm (built from
// this repository's sources by the Pages workflow), the editor is a textarea.
import { PRESETS } from "./presets.js";

const $ = (id) => document.getElementById(id);
const src = $("src"), gutter = $("gutter"), findingsEl = $("findings"), rustEl = $("rust"), statusEl = $("status");
const CORPUS = ["flows", "sql", "secrets", "traits", "stores", "channels", "objects_db", "deep_chain", "state_chain", "known_miss"];

// ---- the compiler ----------------------------------------------------------------
let pz = null;
async function load() {
  const res = fetch("parvez.wasm");
  const { instance } = WebAssembly.instantiateStreaming
    ? await WebAssembly.instantiateStreaming(res).catch(async () => WebAssembly.instantiate(await (await fetch("parvez.wasm")).arrayBuffer()))
    : await WebAssembly.instantiate(await (await res).arrayBuffer());
  pz = instance.exports;
}

function check(code) {
  const bytes = new TextEncoder().encode(code);
  const ptr = pz.pz_alloc(bytes.length);
  new Uint8Array(pz.memory.buffer, ptr, bytes.length).set(bytes);
  try {
    const out = pz.pz_check(ptr, bytes.length);
    return JSON.parse(new TextDecoder().decode(new Uint8Array(pz.memory.buffer, out, pz.pz_result_len())));
  } finally {
    try { pz.pz_free(ptr, bytes.length); } catch { /* the instance may be gone after a trap */ }
  }
}

// ---- rendering ---------------------------------------------------------------------
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function renderGutter(hits = new Set()) {
  const n = src.value.split("\n").length;
  gutter.innerHTML = Array.from({ length: n }, (_, i) => (hits.has(i + 1) ? `<span class="hit">${i + 1}</span>` : `${i + 1}`)).join("\n");
  gutter.scrollTop = src.scrollTop;
}

function goToLine(line) {
  const lines = src.value.split("\n");
  const start = lines.slice(0, line - 1).reduce((a, l) => a + l.length + 1, 0);
  src.focus();
  src.setSelectionRange(start, start + (lines[line - 1] ?? "").length);
  src.scrollTop = Math.max(0, (line - 4) * parseFloat(getComputedStyle(src).lineHeight));
}

function render(r) {
  const hits = new Set();
  let html = "";
  if (r.errors.length) {
    html += `<p class="verdict bad">Doesn't compile</p>`;
    for (const e of r.errors) {
      if (e.line) hits.add(e.line);
      html += `<div class="f"><div class="head">${e.line ? `<span class="line" data-line="${e.line}">line ${e.line}</span>` : ""}</div><p class="msg">${esc(e.message)}</p></div>`;
    }
  } else {
    const open = r.findings.filter((f) => !f.waived);
    html += open.length
      ? `<p class="verdict bad">${open.length} security finding${open.length === 1 ? "" : "s"}: this won't build</p>`
      : `<p class="verdict ok">No security findings</p>`;
    for (const f of r.findings) {
      hits.add(f.line);
      html += `<div class="f${f.waived ? " waived" : ""}"><div class="head"><span class="line" data-line="${f.line}">line ${f.line}</span> · <span class="rule">security[${esc(f.rule)}]</span>${f.waived ? ` · waived: ${esc(f.waived)}` : ""}</div>
        <p class="msg">${esc(f.message)}</p><p class="fix">fix: ${esc(f.fix)}</p>${f.see ? `<p class="see">see: ${esc(f.see)}</p>` : ""}</div>`;
    }
    if (!r.findings.length) html += `<p class="note">Open the <strong>Rust</strong> tab to see what this compiles to. Type and borrow checks run when you build locally with <code>parvez check</code>.</p>`;
  }
  findingsEl.innerHTML = html;
  rustEl.textContent = r.rust ?? (r.errors.length || r.findings.some((f) => !f.waived)
    ? "// Parvez doesn't generate code for a program it refuses. Fix the findings first."
    : "// A program needs `fn main()` or a `route` to generate code.");
  renderGutter(hits);
}

// ---- running ------------------------------------------------------------------------
let timer = null;
function run() {
  if (!pz) return;
  const t0 = performance.now();
  try {
    render(check(src.value));
    statusEl.textContent = `checked in ${(performance.now() - t0).toFixed(0)} ms`;
  } catch (e) {
    statusEl.textContent = "";
    findingsEl.innerHTML = `<p class="verdict bad">Internal compiler error</p><p>The compiler crashed on this input. That's a bug: please <a href="https://github.com/parvez76/parvez/issues/new">report it</a> with the code (the Share link has it).</p>`;
    load().catch(() => {}); // a trapped instance can't be reused
  }
}
function schedule() { clearTimeout(timer); timer = setTimeout(run, 200); renderGutter(); }

// ---- permalinks: the code, deflate-compressed, in the URL hash ---------------------------
const b64url = (bytes) => {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); // chunked: big pastes
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
async function pack(text) {
  const raw = new TextEncoder().encode(text);
  if (!window.CompressionStream) return "t" + b64url(raw);
  const z = new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer());
  return "z" + b64url(z);
}
async function unpack(s) {
  const kind = s[0], bytes = unb64url(s.slice(1));
  if (kind === "t") return new TextDecoder().decode(bytes);
  const out = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).arrayBuffer();
  return new TextDecoder().decode(out);
}

$("share").addEventListener("click", async () => {
  const hash = "#code=" + (await pack(src.value));
  history.replaceState(null, "", hash);
  try { await navigator.clipboard.writeText(location.href); statusEl.textContent = "link copied"; }
  catch { statusEl.textContent = "link is in the address bar"; }
});

// ---- presets ---------------------------------------------------------------------------
const select = $("preset");
for (const p of PRESETS) select.add(new Option(p.title, "builtin:" + p.id));
const group = document.createElement("optgroup");
group.label = "Adversarial corpus: try to break it";
for (const c of CORPUS) group.appendChild(new Option(c === "known_miss" ? "known_miss (documented blind spots)" : c, "corpus:" + c));
select.appendChild(group);

async function loadPreset(value) {
  const [kind, id] = value.split(":");
  if (kind === "builtin") src.value = PRESETS.find((p) => p.id === id).src;
  else src.value = await (await fetch(`presets/${id}.prvz`)).text();
  history.replaceState(null, "", location.pathname);
  src.scrollTop = 0;
  run();
}
select.addEventListener("change", () => loadPreset(select.value));

// ---- editor niceties ---------------------------------------------------------------------
src.addEventListener("input", schedule);
src.addEventListener("scroll", () => { gutter.scrollTop = src.scrollTop; });
src.addEventListener("keydown", (e) => {
  if (e.key === "Tab" && !e.shiftKey) {   // 4 spaces: indentation is syntax
    e.preventDefault();
    src.setRangeText("    ", src.selectionStart, src.selectionEnd, "end");
    schedule();
  }
});
findingsEl.addEventListener("click", (e) => { const l = e.target.dataset?.line; if (l) goToLine(Number(l)); });
for (const [tab, panel] of [["tab-findings", findingsEl], ["tab-rust", rustEl]]) {
  $(tab).addEventListener("click", () => {
    for (const [t, p] of [["tab-findings", findingsEl], ["tab-rust", rustEl]]) { $(t).setAttribute("aria-selected", String(t === tab)); p.hidden = t !== tab; }
  });
}

// ---- start -------------------------------------------------------------------------------
statusEl.textContent = "loading the compiler…";
await load();
const shared = location.hash.match(/^#code=(.+)$/);
if (shared) {
  try { src.value = await unpack(shared[1]); } catch { src.value = PRESETS[0].src; }
  run();
} else {
  await loadPreset("builtin:" + PRESETS[0].id);
}
