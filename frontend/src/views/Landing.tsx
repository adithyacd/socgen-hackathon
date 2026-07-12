import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import * as THREE from "three";

const CSS = `
.landing{--red:#E60028;--ink:#F4F4F5;--muted:#8A8A93;font-family:'Space Grotesk',sans-serif;color:var(--ink);}
.landing canvas{position:fixed;inset:0;width:100vw;height:100vh;z-index:0;display:block}
.landing #redfill{position:fixed;inset:0;z-index:2;pointer-events:none;opacity:0;
  background:radial-gradient(circle at 62% 50%,#ff2a48 0%,#E60028 42%,#a3001c 100%);}

/* top bar */
.landing .lbar{position:fixed;top:22px;left:0;right:0;z-index:5;display:flex;align-items:center;
  justify-content:space-between;padding:0 34px;pointer-events:none}
.landing .brand{display:inline-flex;align-items:center;gap:10px;font-weight:700;font-size:16px}
.landing .mk{width:15px;height:15px;background:linear-gradient(180deg,var(--red) 0 50%,#000 50% 100%)}
.landing .openbtn{pointer-events:auto;cursor:pointer;border:0;background:var(--red);color:#fff;
  font:600 13.5px 'Space Grotesk',sans-serif;letter-spacing:.02em;padding:11px 22px;transition:.16s}
.landing .openbtn:hover{background:#fff;color:var(--red)}

/* left narrative */
.landing .lpanel{position:fixed;top:0;bottom:0;left:0;width:46vw;max-width:560px;z-index:3;pointer-events:none;
  display:flex;flex-direction:column;justify-content:center;padding-left:min(7vw,90px);padding-right:24px;
  background:linear-gradient(90deg,#000 42%,rgba(0,0,0,.72) 68%,transparent 100%)}
.landing .lsec{position:absolute;left:min(7vw,90px);right:24px;max-width:34ch;opacity:0}
.landing .lsec .k{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.28em;text-transform:uppercase;color:var(--red)}
.landing .lsec h3{font-weight:700;font-size:clamp(26px,3vw,38px);line-height:1.06;letter-spacing:-.02em;margin-top:14px}
.landing .lsec p{margin-top:14px;font-size:15px;line-height:1.6;color:#B8B8BF}
.landing .lscroll{position:fixed;left:min(7vw,90px);bottom:32px;z-index:4;pointer-events:none;
  font-family:'JetBrains Mono',monospace;font-size:10.5px;letter-spacing:.24em;text-transform:uppercase;color:var(--muted)}
.landing .lscroll span{display:block;width:1px;height:26px;margin-top:10px;background:linear-gradient(var(--muted),transparent)}

/* end CTA over red */
.landing #lcta{position:fixed;inset:0;z-index:4;display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:22px;text-align:center;opacity:0;pointer-events:none}
.landing #lcta .k{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.3em;text-transform:uppercase;color:rgba(255,255,255,.85)}
.landing #lcta h2{font-weight:700;font-size:clamp(30px,5vw,58px);letter-spacing:-.02em;color:#fff;max-width:16ch;line-height:1.05}
.landing #lcta button{font:600 16px 'Space Grotesk';color:#E60028;background:#fff;border:0;cursor:pointer;padding:15px 30px;transition:.16s}
.landing #lcta button:hover{background:#000;color:#fff;box-shadow:inset 0 0 0 1px #fff}
.landing #lspacer{height:620vh}
@media(prefers-reduced-motion:reduce){.landing .lscroll span{display:none}}
@media(max-width:760px){.landing .lpanel{width:100vw;max-width:none;background:linear-gradient(180deg,#000 60%,transparent)}}
`;

const NARR = 0.56; // fraction of scroll spent on the narrative before the dive

export default function Landing() {
  const navigate = useNavigate();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const html = document.documentElement, body = document.body;
    const root = document.getElementById("root");
    const prev = { hH: html.style.height, bH: body.style.height, rH: root?.style.height ?? "", bg: body.style.background };
    html.style.height = "auto"; body.style.height = "auto";
    if (root) root.style.height = "auto";
    body.style.background = "#000";
    window.scrollTo(0, 0);

    const canvas = canvasRef.current!;
    const clamp = (x: number, a: number, b: number) => Math.max(a, Math.min(b, x));
    const smooth = (e0: number, e1: number, x: number) => { const t = clamp((x - e0) / (e1 - e0), 0, 1); return t * t * (3 - 2 * t); };
    const easeIO = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);

    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, innerWidth / innerHeight, 0.1, 240);
    const camStart = new THREE.Vector3(0, 0, 56);
    camera.position.copy(camStart);
    const group = new THREE.Group(); scene.add(group);

    function disc() {
      const c = document.createElement("canvas"); c.width = c.height = 64;
      const x = c.getContext("2d")!; const g = x.createRadialGradient(32, 32, 0, 32, 32, 32);
      g.addColorStop(0, "rgba(255,255,255,1)"); g.addColorStop(0.3, "rgba(255,255,255,.85)");
      g.addColorStop(1, "rgba(255,255,255,0)"); x.fillStyle = g; x.fillRect(0, 0, 64, 64);
      return new THREE.CanvasTexture(c);
    }
    const discTex = disc();

    const N = 520, pos = new Float32Array(N * 3);
    for (let i = 0; i < N; i++) {
      const r = 30 * Math.cbrt(Math.random());
      const th = Math.random() * Math.PI * 2, ph = Math.acos(2 * Math.random() - 1);
      pos[i * 3] = r * Math.sin(ph) * Math.cos(th);
      pos[i * 3 + 1] = r * Math.sin(ph) * Math.sin(th);
      pos[i * 3 + 2] = r * Math.cos(ph);
    }
    const pgeo = new THREE.BufferGeometry();
    pgeo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    group.add(new THREE.Points(pgeo, new THREE.PointsMaterial({
      size: 0.85, map: discTex, transparent: true, opacity: 0.8, depthWrite: false,
      color: 0xffffff, sizeAttenuation: true, blending: THREE.AdditiveBlending,
    })));

    const lp: number[] = [];
    for (let i = 0; i < N; i += 1) {
      let best = -1, bd = 1e9;
      for (let j = 0; j < N; j++) {
        if (i === j) continue;
        const dx = pos[i * 3] - pos[j * 3], dy = pos[i * 3 + 1] - pos[j * 3 + 1], dz = pos[i * 3 + 2] - pos[j * 3 + 2];
        const d = dx * dx + dy * dy + dz * dz; if (d < bd) { bd = d; best = j; }
      }
      if (best >= 0 && Math.random() < 0.5) lp.push(pos[i * 3], pos[i * 3 + 1], pos[i * 3 + 2], pos[best * 3], pos[best * 3 + 1], pos[best * 3 + 2]);
    }
    const lgeo = new THREE.BufferGeometry();
    lgeo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(lp), 3));
    group.add(new THREE.LineSegments(lgeo, new THREE.LineBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.07 })));

    const C = new THREE.Vector3(9, -4, -7);
    function node(pp: THREE.Vector3, r: number) {
      const m = new THREE.Mesh(new THREE.SphereGeometry(r, 20, 20), new THREE.MeshBasicMaterial({ color: 0xffffff }));
      m.position.copy(pp);
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: discTex, color: 0xe60028, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0, 0, 0); m.add(s); m.userData.glow = s;
      group.add(m); return m;
    }
    const primary = node(C, 0.7);
    const neigh: THREE.Mesh[] = [];
    for (let i = 0; i < 7; i++) {
      const pp = C.clone().add(new THREE.Vector3((Math.random() - 0.5) * 7, (Math.random() - 0.5) * 7, (Math.random() - 0.5) * 7));
      neigh.push(node(pp, 0.34 + Math.random() * 0.12));
    }

    let p = 0;
    const maxScroll = () => document.body.scrollHeight - innerHeight;
    const onScroll = () => { p = clamp(scrollY / maxScroll(), 0, 1); };
    addEventListener("scroll", onScroll, { passive: true });

    const tmp = new THREE.Vector3(), look = new THREE.Vector3(), camEnd = new THREE.Vector3(), dir = new THREE.Vector3();
    const RED = new THREE.Color(0xe60028), WHITE = new THREE.Color(0xffffff), tc = new THREE.Color();

    const redfill = document.getElementById("redfill")!;
    const cta = document.getElementById("lcta")!;
    const s1 = document.getElementById("ls1")!, s2 = document.getElementById("ls2")!, s3 = document.getElementById("ls3")!;
    const panel = document.getElementById("lpanel")!, bar = document.getElementById("lbar")!, scr = document.getElementById("lscroll")!;

    const t0 = performance.now();
    let raf = 0;
    function tick(now: number) {
      const time = (now - t0) / 1000;
      const np = clamp(p / NARR, 0, 1);                       // narrative progress
      const dp = clamp((p - NARR) / (1 - NARR), 0, 1);        // dive progress

      // graph spins with the scroll during the narrative, then holds for the dive
      group.rotation.y = np * Math.PI * 2.4 + dp * 0.35;
      group.rotation.x = 0.14 * Math.sin(np * Math.PI);
      group.position.x = 6 * (1 - smooth(0, 0.4, dp));         // sits right, recenters for the dive

      const pulse = 0.5 + 0.5 * Math.sin(time * 3);
      const gi = smooth(0.05, 0.30, dp);                      // primary ignites
      (primary.material as THREE.MeshBasicMaterial).color.copy(tc.copy(WHITE).lerp(RED, gi));
      const pglow = primary.userData.glow as THREE.Sprite;
      (pglow.material as THREE.SpriteMaterial).opacity = gi * (0.5 + 0.5 * pulse);
      const pg = 0.6 + gi * (3.2 + pulse * 1.4); pglow.scale.set(pg, pg, pg);

      neigh.forEach((n, i) => {
        const thr = 0.22 + i * 0.045; const ni = smooth(thr, thr + 0.1, dp);
        (n.material as THREE.MeshBasicMaterial).color.copy(tc.copy(WHITE).lerp(RED, ni));
        const g = n.userData.glow as THREE.Sprite;
        (g.material as THREE.SpriteMaterial).opacity = ni * 0.7 * (0.6 + 0.4 * pulse);
        const s = 0.5 + ni * (1.8 + pulse * 0.6); g.scale.set(s, s, s);
      });

      primary.getWorldPosition(tmp);
      dir.copy(camStart).sub(tmp).normalize();
      camEnd.copy(tmp).add(dir.multiplyScalar(3.2));
      const t = easeIO(smooth(0.08, 0.82, dp));
      camera.position.lerpVectors(camStart, camEnd, t);
      look.set(0, 0, 0).lerp(tmp, smooth(0.05, 0.35, dp));
      camera.lookAt(look);
      const sw = 1 + smooth(0.5, 1, dp) * 7; primary.scale.set(sw, sw, sw);

      renderer.render(scene, camera);

      // narrative sections cross-fade as you scroll
      s1.style.opacity = String(smooth(0.02, 0.08, np) - smooth(0.26, 0.34, np));
      s2.style.opacity = String(Math.max(0, smooth(0.30, 0.38, np) - smooth(0.58, 0.66, np)));
      s3.style.opacity = String(Math.max(0, smooth(0.62, 0.70, np) - smooth(0.0, 0.08, dp)));
      scr.style.opacity = String((1 - smooth(0.05, 0.16, np)) * (1 - smooth(0.6, 0.9, np)));
      panel.style.opacity = String(1 - smooth(0.0, 0.12, dp));
      bar.style.opacity = String(1 - smooth(0.82, 0.95, dp));
      redfill.style.opacity = String(smooth(0.72, 1, dp));
      const ctaP = smooth(0.85, 0.97, dp);
      cta.style.opacity = String(ctaP); cta.style.pointerEvents = ctaP > 0.5 ? "auto" : "none";

      raf = requestAnimationFrame(tick);
    }
    raf = requestAnimationFrame(tick);

    const resize = () => { renderer.setSize(innerWidth, innerHeight); camera.aspect = innerWidth / innerHeight; camera.updateProjectionMatrix(); };
    addEventListener("resize", resize); resize();

    return () => {
      cancelAnimationFrame(raf);
      removeEventListener("scroll", onScroll);
      removeEventListener("resize", resize);
      renderer.dispose();
      html.style.height = prev.hH; body.style.height = prev.bH;
      if (root) root.style.height = prev.rH; body.style.background = prev.bg;
      window.scrollTo(0, 0);
    };
  }, []);

  return (
    <div className="landing">
      <style>{CSS}</style>
      <canvas ref={canvasRef} />
      <div id="redfill" />

      <div className="lbar" id="lbar">
        <span className="brand"><span className="mk" />Sentinel</span>
        <button className="openbtn" onClick={() => navigate("/portfolio")}>Open app →</button>
      </div>

      <div className="lpanel" id="lpanel">
        <div className="lsec" id="ls1">
          <div className="k">What it does</div>
          <h3>See every dependency at once.</h3>
          <p>Sentinel maps each application to its full dependency tree, resolves the transitive chains, and scores supply-chain risk across the whole portfolio.</p>
        </div>
        <div className="lsec" id="ls2">
          <div className="k">How it works</div>
          <h3>Six analyzers, one graph.</h3>
          <p>A dependency graph feeds version-aware CVE matching, transitive-path resolution, license and maintenance checks, and exploitability-ranked scoring — measured against the official benchmark.</p>
        </div>
        <div className="lsec" id="ls3">
          <div className="k">The edge</div>
          <h3>It sees what a CVE list can’t.</h3>
          <p>Reachability-aware prioritization, a remediation optimizer, and typosquat &amp; malicious-package hunting — it even audits the benchmark’s own labels.</p>
        </div>
      </div>

      <div className="lscroll" id="lscroll">Scroll down<span /></div>

      <div id="lcta">
        <div className="k">One vulnerable node, and it spreads</div>
        <h2>See which apps are exposed.</h2>
        <button onClick={() => navigate("/portfolio")}>Open the app →</button>
      </div>

      <div id="lspacer" />
    </div>
  );
}
