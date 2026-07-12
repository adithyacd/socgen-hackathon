import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import * as THREE from "three";

const CSS = `
.landing{--red:#E50A30;--ink:#F3F2EF;--muted:#9A9AA2;font-family:'Space Grotesk',sans-serif;}
.landing canvas{position:fixed;inset:0;width:100vw;height:100vh;z-index:0;display:block}
.landing #redfill{position:fixed;inset:0;z-index:2;pointer-events:none;opacity:0;
  background:radial-gradient(circle at 50% 50%,#ff1f42 0%,#E50A30 42%,#b30020 100%);}
.landing .caps{position:fixed;left:0;right:0;bottom:12vh;z-index:3;text-align:center;pointer-events:none}
.landing .cap{position:absolute;left:0;right:0;opacity:0}
.landing .cap .k{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.3em;text-transform:uppercase;color:var(--muted)}
.landing .cap .t{font-weight:700;font-size:clamp(22px,3.4vw,40px);letter-spacing:-.02em;color:var(--ink);margin-top:12px}
.landing .cap .t b{color:var(--red)}
.landing #ltop{position:fixed;top:26px;left:0;right:0;z-index:3;text-align:center;pointer-events:none}
.landing #ltop .brand{display:inline-flex;align-items:center;gap:10px;font-weight:700;font-size:16px;color:var(--ink)}
.landing #ltop .mk{width:16px;height:16px;background:linear-gradient(180deg,var(--red) 0 50%,#0c0c0e 50% 100%)}
.landing #lhint{position:fixed;bottom:30px;left:0;right:0;z-index:3;text-align:center;pointer-events:none;
  font-family:'JetBrains Mono',monospace;font-size:10.5px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted)}
.landing #lhint span{display:block;width:1px;height:24px;margin:10px auto 0;background:linear-gradient(var(--muted),transparent)}
.landing #lcta{position:fixed;inset:0;z-index:4;display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:22px;text-align:center;opacity:0;pointer-events:none}
.landing #lcta .k{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.3em;text-transform:uppercase;color:rgba(255,255,255,.8)}
.landing #lcta h2{font-weight:700;font-size:clamp(30px,5.4vw,60px);letter-spacing:-.02em;color:#fff;max-width:16ch;line-height:1.05}
.landing #lcta button{font-family:'Space Grotesk';font-weight:600;font-size:16px;color:#E50A30;background:#fff;border:0;cursor:pointer;
  padding:15px 30px;transition:.18s}
.landing #lcta button:hover{background:#050506;color:#fff;box-shadow:inset 0 0 0 1px #fff}
.landing #lspacer{height:560vh}
@media(prefers-reduced-motion:reduce){.landing #lhint span{display:none}}
`;

export default function Landing() {
  const navigate = useNavigate();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    // Let the page grow tall enough to scroll (the dashboard pins these to 100%).
    const html = document.documentElement, body = document.body;
    const root = document.getElementById("root");
    const prev = { hH: html.style.height, bH: body.style.height, rH: root?.style.height ?? "", bg: body.style.background };
    html.style.height = "auto"; body.style.height = "auto";
    if (root) root.style.height = "auto";
    body.style.background = "#050506";
    window.scrollTo(0, 0);

    const canvas = canvasRef.current!;
    const clamp = (x: number, a: number, b: number) => Math.max(a, Math.min(b, x));
    const smooth = (e0: number, e1: number, x: number) => { const t = clamp((x - e0) / (e1 - e0), 0, 1); return t * t * (3 - 2 * t); };
    const easeIO = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

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
    const points = new THREE.Points(pgeo, new THREE.PointsMaterial({
      size: 0.85, map: discTex, transparent: true, opacity: 0.8, depthWrite: false,
      color: 0xffffff, sizeAttenuation: true, blending: THREE.AdditiveBlending,
    }));
    group.add(points);

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
    function node(p: THREE.Vector3, r: number) {
      const m = new THREE.Mesh(new THREE.SphereGeometry(r, 20, 20), new THREE.MeshBasicMaterial({ color: 0xffffff }));
      m.position.copy(p);
      const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: discTex, color: 0xe50a30, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }));
      s.scale.set(0, 0, 0); m.add(s); m.userData.glow = s;
      group.add(m); return m;
    }
    const primary = node(C, 0.7);
    const neigh: THREE.Mesh[] = [];
    for (let i = 0; i < 7; i++) {
      const p = C.clone().add(new THREE.Vector3((Math.random() - 0.5) * 7, (Math.random() - 0.5) * 7, (Math.random() - 0.5) * 7));
      neigh.push(node(p, 0.34 + Math.random() * 0.12));
    }

    let p = 0;
    const maxScroll = () => document.body.scrollHeight - innerHeight;
    const onScroll = () => { p = clamp(scrollY / maxScroll(), 0, 1); };
    addEventListener("scroll", onScroll, { passive: true });

    const tmp = new THREE.Vector3(), look = new THREE.Vector3(), camEnd = new THREE.Vector3(), dir = new THREE.Vector3();
    const RED = new THREE.Color(0xe50a30), WHITE = new THREE.Color(0xffffff), tc = new THREE.Color();

    const redfill = document.getElementById("redfill")!;
    const cta = document.getElementById("lcta")!;
    const c1 = document.getElementById("lc1")!, c2 = document.getElementById("lc2")!, c3 = document.getElementById("lc3")!;
    const hint = document.getElementById("lhint")!, topEl = document.getElementById("ltop")!;

    const t0 = performance.now();
    let raf = 0;
    function tick(now: number) {
      const time = (now - t0) / 1000;
      const rf = (reduce ? 0 : 1) * (1 - smooth(0.12, 0.42, p));
      group.rotation.y += 0.0016 * rf;
      group.rotation.x = 0.12 * Math.sin(time * 0.15) * rf;

      const gi = smooth(0.16, 0.36, p);
      const pulse = 0.5 + 0.5 * Math.sin(time * 3);
      (primary.material as THREE.MeshBasicMaterial).color.copy(tc.copy(WHITE).lerp(RED, gi));
      const pglow = primary.userData.glow as THREE.Sprite;
      (pglow.material as THREE.SpriteMaterial).opacity = gi * (0.5 + 0.5 * pulse);
      const pg = 0.6 + gi * (3.2 + pulse * 1.4); pglow.scale.set(pg, pg, pg);

      neigh.forEach((n, i) => {
        const thr = 0.34 + i * 0.035; const ni = smooth(thr, thr + 0.09, p);
        (n.material as THREE.MeshBasicMaterial).color.copy(tc.copy(WHITE).lerp(RED, ni));
        const g = n.userData.glow as THREE.Sprite;
        (g.material as THREE.SpriteMaterial).opacity = ni * 0.7 * (0.6 + 0.4 * pulse);
        const s = 0.5 + ni * (1.8 + pulse * 0.6); g.scale.set(s, s, s);
      });

      primary.getWorldPosition(tmp);
      dir.copy(camStart).sub(tmp).normalize();
      camEnd.copy(tmp).add(dir.multiplyScalar(3.2));
      const t = easeIO(smooth(0.2, 0.9, p));
      camera.position.lerpVectors(camStart, camEnd, t);
      look.set(0, 0, 0).lerp(tmp, smooth(0.15, 0.45, p));
      camera.lookAt(look);
      const sw = 1 + smooth(0.6, 1, p) * 7; primary.scale.set(sw, sw, sw);

      renderer.render(scene, camera);

      redfill.style.opacity = String(smooth(0.8, 1, p));
      const ctaP = smooth(0.9, 0.985, p);
      cta.style.opacity = String(ctaP); cta.style.pointerEvents = ctaP > 0.5 ? "auto" : "none";
      c1.style.opacity = String(1 - smooth(0.1, 0.2, p));
      c2.style.opacity = String(Math.max(0, smooth(0.2, 0.28, p) - smooth(0.46, 0.54, p)));
      c3.style.opacity = String(Math.max(0, smooth(0.5, 0.58, p) - smooth(0.74, 0.82, p)));
      hint.style.opacity = String(1 - smooth(0.04, 0.14, p));
      topEl.style.opacity = String(1 - smooth(0.78, 0.9, p));
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
      <div id="ltop"><span className="brand"><span className="mk" />Sentinel</span></div>
      <div className="caps">
        <div className="cap" id="lc1"><div className="k">Third-party &amp; software risk</div><div className="t">Every library. Every app. One graph.</div></div>
        <div className="cap" id="lc2"><div className="k">Detected</div><div className="t">One dependency is <b>vulnerable.</b></div></div>
        <div className="cap" id="lc3"><div className="k">Transitive risk</div><div className="t">And it <b>spreads</b> to everything it touches.</div></div>
      </div>
      <div id="lhint">Scroll to go in<span /></div>
      <div id="lcta">
        <div className="k">Sentinel caught it first</div>
        <h2>See which apps are exposed.</h2>
        <button onClick={() => navigate("/portfolio")}>Open the app →</button>
      </div>
      <div id="lspacer" />
    </div>
  );
}
