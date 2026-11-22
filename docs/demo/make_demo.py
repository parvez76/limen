#!/usr/bin/env python3
"""Generate demo.svg: a looping terminal animation built from the REAL output of
`parvez` (run at generation time), so the demo can't drift from the compiler.
   python3 docs/demo/make_demo.py [path-to-parvez]"""
import html, os, shutil, subprocess, sys, tempfile, textwrap

PARVEZ = sys.argv[1] if len(sys.argv) > 1 else shutil.which("parvez") or "parvez"
UNGUARDED = '''route GET "/admin/users" -> str:
    ret "everyone"
'''
GUARDED = '''fn staff(req) -> str!:
    ret req.header("x-user").unwrap_or_default()

@guard(staff)
route GET "/admin/users" (auth) -> str:
    ret "hello {auth}"
'''

def run(args, cwd):
    p = subprocess.run([PARVEZ, *args], cwd=cwd, capture_output=True, text=True, env={**os.environ, "NO_COLOR": "1"})
    return (p.stdout + p.stderr).strip()

with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, "admin.prvz"), "w").write(UNGUARDED)
    refused = run(["check", "admin.prvz"], d).splitlines()[-1]
    open(os.path.join(d, "admin.prvz"), "w").write(GUARDED)
    lint_ok = run(["lint", "admin.prvz"], d).splitlines()[-1]
    routes = run(["routes", "admin.prvz"], d).splitlines()[:2]

# (kind, text): kind = cmd (typed), out, err, ok, file, note
steps = [("note", "# An agent wrote an admin endpoint. It forgot the permission check."),
         ("cmd", "cat admin.prvz")]
steps += [("file", l) for l in UNGUARDED.rstrip().splitlines()]
steps += [("cmd", "parvez check admin.prvz")]
steps += [("err", l) for l in textwrap.wrap(refused, 96, subsequent_indent="  ")]
steps += [("note", "# Add a guard: say who may call the route."), ("cmd", "cat admin.prvz")]
steps += [("file", l) for l in GUARDED.rstrip().splitlines()]
steps += [("cmd", "parvez lint admin.prvz"), ("ok", lint_ok), ("cmd", "parvez routes admin.prvz")]
steps += [("out", l) for l in routes]

LH, PAD, TOP, CW = 19, 18, 44, 7.85         # line height, padding, title bar, char width (px)
W = 880
H = TOP + PAD * 2 + LH * len(steps)
TYPE, PAUSE = 0.045, 0.5                    # seconds per typed character; pause after a step
colors = {"cmd": "#e6edf3", "out": "#c9d1d9", "err": "#ff7b72", "ok": "#56d364", "file": "#d2a8ff", "note": "#8b949e"}

t, timeline = 0.6, []
for kind, text in steps:
    dur = len(text) * TYPE if kind == "cmd" else 0
    timeline.append((kind, text, t, dur))
    t += dur + (PAUSE if kind in ("cmd", "note") else 0.12)
TOTAL = t + 4.0                              # hold the final screen, then loop

def pct(x): return f"{100 * x / TOTAL:.3f}%"

css, body = [], []
for i, (kind, text, start, dur) in enumerate(timeline):
    y = TOP + PAD + LH * i + 13
    shown = ("$ " if kind == "cmd" else "") + text
    esc = html.escape(shown)
    color = colors[kind]
    if kind == "cmd":
        width = len(shown) * CW + 4
        css.append(f"@keyframes c{i}{{0%,{pct(start)}{{width:0}}{pct(start+dur)},99%{{width:{width:.0f}px}}100%{{width:0}}}}"
                   f"#r{i}{{animation:c{i} {TOTAL:.2f}s steps(1,end) infinite;animation-timing-function:linear}}")
        body.append(f'<clipPath id="k{i}"><rect id="r{i}" x="{PAD}" y="{y-14}" height="{LH}" width="0"/></clipPath>'
                    f'<text x="{PAD}" y="{y}" fill="{color}" clip-path="url(#k{i})">{esc}</text>')
    else:
        # fill-opacity, not opacity: opacity animations run on the compositor, which some renderers skip
        css.append(f"@keyframes s{i}{{0%,{pct(start)}{{fill-opacity:0}}{pct(start+0.01)},99%{{fill-opacity:1}}100%{{fill-opacity:0}}}}"
                   f"#t{i}{{fill-opacity:0;animation:s{i} {TOTAL:.2f}s linear infinite}}")
        body.append(f'<text id="t{i}" x="{PAD}" y="{y}" fill="{color}">{esc}</text>')

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="Parvez refuses an admin route without an access policy; adding @guard fixes it">
<title>Parvez: the unguarded route doesn't compile; one line fixes it</title>
<style>text{{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre}}{"".join(css)}</style>
<rect width="{W}" height="{H}" rx="10" fill="#0d1117"/>
<rect width="{W}" height="{TOP-8}" rx="10" fill="#161b22"/><rect y="{TOP-18}" width="{W}" height="10" fill="#161b22"/>
<circle cx="22" cy="18" r="6" fill="#ff5f56"/><circle cx="42" cy="18" r="6" fill="#ffbd2e"/><circle cx="62" cy="18" r="6" fill="#27c93f"/>
<text x="{W/2}" y="22" fill="#8b949e" text-anchor="middle">parvez</text>
{"".join(body)}
</svg>
'''
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo.svg")
open(out, "w").write(svg)
print(f"{out}: {len(svg)//1024} KB, {len(steps)} lines, {TOTAL:.1f} s loop")
