// The playground must report exactly what `limen lint` reports: run every
// single-file case of the adversarial corpus through the WebAssembly build and
// compare with its `# expect:` / `# known-miss:` annotations. The deep-chain
// cases double as the stack test (WebAssembly's stack is much smaller than the CLI's).
//   node playground/test.mjs <limen_playground.wasm>
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = process.argv[2] ?? join(here, "target/wasm32-unknown-unknown/release/limen_playground.wasm");
const corpus = join(here, "..", "tests", "security_corpus");
const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath));
const pz = instance.exports;

function check(src) {
  const bytes = new TextEncoder().encode(src);
  const ptr = pz.lm_alloc(bytes.length);
  new Uint8Array(pz.memory.buffer, ptr, bytes.length).set(bytes);
  const out = pz.lm_check(ptr, bytes.length);
  pz.lm_free(ptr, bytes.length);
  return JSON.parse(new TextDecoder().decode(new Uint8Array(pz.memory.buffer, out, pz.lm_result_len())));
}

let failures = 0, files = 0, expected = 0;
for (const file of readdirSync(corpus).filter((f) => f.endsWith(".lmn")).sort()) {
  const src = readFileSync(join(corpus, file), "utf8");
  if (/^import /m.test(src)) continue; // multi-file cases need the CLI
  files++;
  const want = new Set(), miss = new Set();
  src.split("\n").forEach((line, i) => {
    const e = line.match(/# expect: ([a-z-]+)/), m = line.match(/# known-miss: ([a-z-]+)/);
    if (e) want.add(`${i + 1}:${e[1]}`);
    if (m) miss.add(`${i + 1}:${m[1]}`);
  });
  expected += want.size;
  const t0 = performance.now();
  const r = check(src);
  const ms = (performance.now() - t0).toFixed(1);
  if (r.errors.length) { console.log(`FAIL ${file}: ${JSON.stringify(r.errors)}`); failures++; continue; }
  const got = new Set(r.findings.filter((f) => !f.waived).map((f) => `${f.line}:${f.rule}`));
  const missed = [...want].filter((x) => !got.has(x));
  const extra = [...got].filter((x) => !want.has(x));
  const caughtKnown = [...miss].filter((x) => got.has(x));
  if (missed.length || extra.length || caughtKnown.length) {
    failures++;
    console.log(`FAIL ${file}: missed ${missed} | extra ${extra} | known-miss caught ${caughtKnown}`);
  } else {
    console.log(`ok   ${file} (${got.size} findings, ${ms} ms)`);
  }
}
// a clean program produces Rust, and an unguarded route is refused
const clean = check('@public("demo")\nroute GET "/" -> str:\n    ret "hi"\n');
if (!clean.ok || !clean.rust || !clean.rust.includes("axum")) { console.log("FAIL clean program produced no Rust"); failures++; }
const open = check('route GET "/admin" -> str:\n    ret "x"\n');
if (!open.errors[0]?.message.includes("no access policy") || open.errors[0]?.line !== 1) { console.log("FAIL unguarded route", JSON.stringify(open.errors)); failures++; }
console.log(`${files} corpus files, ${expected} expected findings, ${failures} failure(s); compiler ${clean.version}`);
process.exit(failures ? 1 : 0);
