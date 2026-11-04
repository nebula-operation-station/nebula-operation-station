// SPDX-License-Identifier: AGPL-3.0-or-later
//
// WebGL2 backend (ADR 0009 D4): instanced quads for stars, beams and
// particles, one fragment-shader nebula per VLAN, and HDR bloom when
// EXT_color_buffer_float is available. The number of draw calls per frame
// is constant (at most eight) regardless of the model size.
//
// On context loss the backend stops drawing and calls onLost; the caller
// then switches to the Canvas 2D backend on a fresh canvas element.
//
// Particle motion in PARTICLE_VS matches particleT in canvas2d.js.

const QUAD = `
const vec2 CORNERS[6] = vec2[6](vec2(-1.0, -1.0), vec2(1.0, -1.0), vec2(1.0, 1.0),
                                vec2(-1.0, -1.0), vec2(1.0, 1.0), vec2(-1.0, 1.0));
uniform vec2 u_center;
uniform float u_scale;
uniform vec2 u_viewport;
vec4 toClip(vec2 world, vec2 offsetPx) {
  vec2 px = (world - u_center) * u_scale + offsetPx;
  vec2 ndc = px * 2.0 / u_viewport;
  return vec4(ndc.x, -ndc.y, 0.0, 1.0);
}
`;

const STAR_VS = `#version 300 es
layout(location = 0) in vec2 a_pos;
layout(location = 1) in float a_radius;
layout(location = 2) in vec3 a_color;
layout(location = 3) in float a_bright;
${QUAD}
out vec2 v_uv;
out vec3 v_color;
out float v_bright;
void main() {
  vec2 c = CORNERS[gl_VertexID];
  float core = max(1.2, a_radius * u_scale);
  v_uv = c;
  v_color = a_color;
  v_bright = a_bright;
  gl_Position = toClip(a_pos, c * core * 3.2);
}`;

const STAR_FS = `#version 300 es
precision highp float;
in vec2 v_uv;
in vec3 v_color;
in float v_bright;
out vec4 o;
void main() {
  float d = length(v_uv);
  if (d > 1.0) discard;
  float core = smoothstep(0.34, 0.0, d);
  float glow = exp(-d * d * 9.0);
  vec3 col = mix(v_color, vec3(1.0), core * 0.85) * (core * 2.2 + glow * 0.9);
  o = vec4(col * v_bright, 1.0);
}`;

const BEAM_VS = `#version 300 es
layout(location = 0) in vec2 a_a;
layout(location = 1) in vec2 a_b;
layout(location = 2) in float a_width;
layout(location = 3) in vec3 a_color;
layout(location = 4) in float a_bright;
${QUAD}
out float v_across;
out vec3 v_color;
out float v_bright;
out float v_core;
void main() {
  vec2 c = CORNERS[gl_VertexID];
  vec2 pa = (a_a - u_center) * u_scale;
  vec2 pb = (a_b - u_center) * u_scale;
  vec2 d = pb - pa;
  float len = length(d);
  vec2 dir = len > 1e-4 ? d / len : vec2(1.0, 0.0);
  vec2 normal = vec2(-dir.y, dir.x);
  float halfW = a_width * 1.5 + 1.5;
  vec2 px = mix(pa, pb, c.x * 0.5 + 0.5) + normal * c.y * halfW;
  v_across = c.y;
  v_core = a_width * 0.5 / halfW;
  v_color = a_color;
  v_bright = a_bright;
  vec2 ndc = px * 2.0 / u_viewport;
  gl_Position = vec4(ndc.x, -ndc.y, 0.0, 1.0);
}`;

const BEAM_FS = `#version 300 es
precision highp float;
in float v_across;
in vec3 v_color;
in float v_bright;
in float v_core;
out vec4 o;
void main() {
  float a = abs(v_across);
  float core = 1.0 - smoothstep(v_core * 0.6, v_core + 0.05, a);
  float glow = exp(-a * a * 6.0) * 0.25;
  o = vec4(v_color * v_bright * (core * 0.7 + glow), 1.0);
}`;

const PARTICLE_VS = `#version 300 es
layout(location = 0) in vec2 a_a;
layout(location = 1) in vec2 a_b;
layout(location = 2) in vec3 a_color;
layout(location = 3) in vec4 a_motion; // phase, dir, speed, size
${QUAD}
uniform float u_time;
out vec2 v_uv;
out vec3 v_color;
void main() {
  vec2 c = CORNERS[gl_VertexID];
  float t = fract(a_motion.x + u_time * a_motion.z);
  if (a_motion.y < 0.0) t = 1.0 - t;
  v_uv = c;
  v_color = a_color;
  gl_Position = toClip(mix(a_a, a_b, t), c * a_motion.w);
}`;

const PARTICLE_FS = `#version 300 es
precision highp float;
in vec2 v_uv;
in vec3 v_color;
out vec4 o;
void main() {
  float d = dot(v_uv, v_uv);
  if (d > 1.0) discard;
  o = vec4(mix(v_color, vec3(1.0), 0.35) * exp(-d * 4.0) * 1.6, 1.0);
}`;

const NEBULA_VS = `#version 300 es
layout(location = 0) in vec2 a_pos;
layout(location = 1) in float a_radius;
layout(location = 2) in vec3 a_color;
layout(location = 3) in float a_seed;
${QUAD}
out vec2 v_uv;
out vec2 v_world;
out vec3 v_color;
out float v_seed;
void main() {
  vec2 c = CORNERS[gl_VertexID];
  v_uv = c;
  v_world = a_pos + c * a_radius;
  v_color = a_color;
  v_seed = a_seed;
  gl_Position = toClip(a_pos, c * a_radius * u_scale);
}`;

const NEBULA_FS = `#version 300 es
precision highp float;
in vec2 v_uv;
in vec2 v_world;
in vec3 v_color;
in float v_seed;
uniform float u_time;
out vec4 o;
float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
float noise(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), u.x),
             mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), u.x), u.y);
}
float fbm(vec2 p) {
  float v = 0.0;
  float a = 0.5;
  for (int i = 0; i < 5; i++) {
    v += a * noise(p);
    p = p * 2.03 + vec2(17.0, 9.0);
    a *= 0.5;
  }
  return v;
}
void main() {
  float d = length(v_uv);
  if (d > 1.0) discard;
  float falloff = 1.0 - smoothstep(0.0, 1.0, d);
  vec2 p = v_world * 0.012 + vec2(v_seed * 97.0, v_seed * 31.0) + vec2(u_time * 0.01, 0.0);
  float n = fbm(p + fbm(p * 0.7));
  float density = falloff * falloff * (0.35 + 0.65 * n);
  o = vec4(v_color * density * 0.28, 1.0);
}`;

const FULLSCREEN_VS = `#version 300 es
out vec2 v_uv;
void main() {
  vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));
  v_uv = p;
  gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}`;

const BRIGHT_FS = `#version 300 es
precision highp float;
in vec2 v_uv;
uniform sampler2D u_tex;
out vec4 o;
void main() {
  vec3 c = texture(u_tex, v_uv).rgb;
  float l = max(c.r, max(c.g, c.b));
  o = vec4(c * smoothstep(0.7, 1.4, l), 1.0);
}`;

const BLUR_FS = `#version 300 es
precision highp float;
in vec2 v_uv;
uniform sampler2D u_tex;
uniform vec2 u_step;
out vec4 o;
void main() {
  const float w[5] = float[5](0.227027, 0.1945946, 0.1216216, 0.054054, 0.016216);
  vec3 c = texture(u_tex, v_uv).rgb * w[0];
  for (int i = 1; i < 5; i++) {
    vec2 off = u_step * float(i) * 1.5;
    c += texture(u_tex, v_uv + off).rgb * w[i];
    c += texture(u_tex, v_uv - off).rgb * w[i];
  }
  o = vec4(c, 1.0);
}`;

const COMPOSITE_FS = `#version 300 es
precision highp float;
in vec2 v_uv;
uniform sampler2D u_scene;
uniform sampler2D u_bloom;
uniform vec3 u_background;
out vec4 o;
void main() {
  vec3 c = texture(u_scene, v_uv).rgb + texture(u_bloom, v_uv).rgb * 1.1;
  c = vec3(1.0) - exp(-c * 1.2);
  o = vec4(u_background + c, 1.0);
}`;

const BACKGROUND = [0.02, 0.027, 0.05];

function compile(gl, type, src) {
  const sh = gl.createShader(type);
  gl.shaderSource(sh, src);
  gl.compileShader(sh);
  if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS) && !gl.isContextLost()) {
    const log = gl.getShaderInfoLog(sh);
    gl.deleteShader(sh);
    throw new Error("compile shader: " + log);
  }
  return sh;
}

function program(gl, vs, fs) {
  const p = gl.createProgram();
  const v = compile(gl, gl.VERTEX_SHADER, vs);
  const f = compile(gl, gl.FRAGMENT_SHADER, fs);
  gl.attachShader(p, v);
  gl.attachShader(p, f);
  gl.linkProgram(p);
  gl.deleteShader(v);
  gl.deleteShader(f);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS) && !gl.isContextLost()) {
    throw new Error("link program: " + gl.getProgramInfoLog(p));
  }
  const uniforms = new Map();
  const n = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS) || 0;
  for (let i = 0; i < n; i++) {
    const info = gl.getActiveUniform(p, i);
    uniforms.set(info.name, gl.getUniformLocation(p, info.name));
  }
  return { p, u: (name) => uniforms.get(name) || null };
}

// instanced builds a VAO whose per-instance attributes are interleaved in
// one buffer. fields: [size per location], in location order.
function instanced(gl, fields) {
  const vao = gl.createVertexArray();
  const buf = gl.createBuffer();
  const floats = fields.reduce((a, b) => a + b, 0);
  gl.bindVertexArray(vao);
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  let off = 0;
  fields.forEach((size, loc) => {
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, size, gl.FLOAT, false, floats * 4, off * 4);
    gl.vertexAttribDivisor(loc, 1);
    off += size;
  });
  gl.bindVertexArray(null);
  return { vao, buf, floats, count: 0 };
}

function upload(gl, inst, data, count) {
  gl.bindBuffer(gl.ARRAY_BUFFER, inst.buf);
  gl.bufferData(gl.ARRAY_BUFFER, data, gl.DYNAMIC_DRAW);
  inst.count = count;
}

function target(gl, w, h) {
  const tex = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D, tex);
  gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA16F, w, h, 0, gl.RGBA, gl.HALF_FLOAT, null);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  const fb = gl.createFramebuffer();
  gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
  gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
  const ok = gl.checkFramebufferStatus(gl.FRAMEBUFFER) === gl.FRAMEBUFFER_COMPLETE;
  gl.bindFramebuffer(gl.FRAMEBUFFER, null);
  return { tex, fb, w, h, ok };
}

function freeTarget(gl, t) {
  if (!t) return;
  gl.deleteTexture(t.tex);
  gl.deleteFramebuffer(t.fb);
}

/**
 * createWebGL2Backend returns a WebGL2 backend for canvas, or null if the
 * browser offers no WebGL2 context. It throws if shaders fail to build, so
 * the caller can fall back to Canvas 2D. onLost is called once when the
 * context is lost.
 */
export function createWebGL2Backend(canvas, onLost) {
  const gl = canvas.getContext("webgl2", { alpha: false, antialias: false, depth: false, stencil: false, premultipliedAlpha: false, preserveDrawingBuffer: false });
  if (!gl) return null;

  let lost = false;
  const handleLost = (ev) => {
    ev.preventDefault();
    if (lost) return;
    lost = true;
    onLost();
  };
  canvas.addEventListener("webglcontextlost", handleLost);

  const bloom = gl.getExtension("EXT_color_buffer_float") !== null;
  const progs = {
    star: program(gl, STAR_VS, STAR_FS),
    beam: program(gl, BEAM_VS, BEAM_FS),
    particle: program(gl, PARTICLE_VS, PARTICLE_FS),
    nebula: program(gl, NEBULA_VS, NEBULA_FS),
  };
  if (bloom) {
    progs.bright = program(gl, FULLSCREEN_VS, BRIGHT_FS);
    progs.blur = program(gl, FULLSCREEN_VS, BLUR_FS);
    progs.composite = program(gl, FULLSCREEN_VS, COMPOSITE_FS);
  }
  const stars = instanced(gl, [2, 1, 3, 1]);
  const beams = instanced(gl, [2, 2, 1, 3, 1]);
  const particles = instanced(gl, [2, 2, 3, 4]);
  const nebulae = instanced(gl, [2, 1, 3, 1]);
  const emptyVao = gl.createVertexArray();
  let targets = null;

  function ensureTargets(w, h) {
    if (!bloom) return null;
    if (targets && targets.scene.w === w && targets.scene.h === h) return targets;
    if (targets) {
      freeTarget(gl, targets.scene);
      freeTarget(gl, targets.a);
      freeTarget(gl, targets.b);
    }
    const hw = Math.max(1, w >> 1);
    const hh = Math.max(1, h >> 1);
    targets = { scene: target(gl, w, h), a: target(gl, hw, hh), b: target(gl, hw, hh) };
    if (!targets.scene.ok || !targets.a.ok || !targets.b.ok) {
      throw new Error("create bloom framebuffers: incomplete");
    }
    return targets;
  }

  function setView(prog, cam, time) {
    gl.useProgram(prog.p);
    gl.uniform2f(prog.u("u_center"), cam.cx, cam.cy);
    gl.uniform1f(prog.u("u_scale"), cam.scale);
    gl.uniform2f(prog.u("u_viewport"), cam.width, cam.height);
    const ut = prog.u("u_time");
    if (ut) gl.uniform1f(ut, time);
  }

  function drawInstanced(prog, inst, cam, time) {
    if (inst.count === 0) return;
    setView(prog, cam, time);
    gl.bindVertexArray(inst.vao);
    gl.drawArraysInstanced(gl.TRIANGLES, 0, 6, inst.count);
  }

  function fullscreen(prog, out, w, h) {
    gl.bindFramebuffer(gl.FRAMEBUFFER, out ? out.fb : null);
    gl.viewport(0, 0, w, h);
    gl.useProgram(prog.p);
    gl.bindVertexArray(emptyVao);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  }

  function bindTex(unit, tex, prog, name) {
    gl.activeTexture(gl.TEXTURE0 + unit);
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.uniform1i(prog.u(name), unit);
  }

  return {
    name: bloom ? "webgl2" : "webgl2 (no bloom)",
    setScene(scene) {
      if (lost) return;
      const s = new Float32Array(scene.stars.length * stars.floats);
      scene.stars.forEach((st, i) => {
        s.set([st.x, st.y, st.r, st.rgb[0], st.rgb[1], st.rgb[2], st.brightness], i * stars.floats);
      });
      upload(gl, stars, s, scene.stars.length);

      const b = new Float32Array(scene.beams.length * beams.floats);
      scene.beams.forEach((bm, i) => {
        b.set([bm.ax, bm.ay, bm.bx, bm.by, bm.width, bm.rgb[0], bm.rgb[1], bm.rgb[2], bm.brightness], i * beams.floats);
      });
      upload(gl, beams, b, scene.beams.length);

      const p = new Float32Array(scene.particles.length * particles.floats);
      scene.particles.forEach((pt, i) => {
        const bm = scene.beams[pt.beam];
        p.set([bm.ax, bm.ay, bm.bx, bm.by, bm.rgb[0], bm.rgb[1], bm.rgb[2], pt.phase, pt.dir, pt.speed, 2.5 + bm.width * 0.6], i * particles.floats);
      });
      upload(gl, particles, p, scene.particles.length);

      const n = new Float32Array(scene.nebulae.length * nebulae.floats);
      scene.nebulae.forEach((nb, i) => {
        n.set([nb.x, nb.y, nb.r, nb.rgb[0], nb.rgb[1], nb.rgb[2], nb.seed], i * nebulae.floats);
      });
      upload(gl, nebulae, n, scene.nebulae.length);
    },
    isLost() {
      return lost || gl.isContextLost();
    },
    render(cam, dpr, time) {
      if (lost || gl.isContextLost()) return;
      const w = gl.drawingBufferWidth;
      const h = gl.drawingBufferHeight;
      const t = ensureTargets(w, h);
      gl.bindFramebuffer(gl.FRAMEBUFFER, t ? t.scene.fb : null);
      gl.viewport(0, 0, w, h);
      if (t) {
        gl.clearColor(0, 0, 0, 1);
      } else {
        gl.clearColor(BACKGROUND[0], BACKGROUND[1], BACKGROUND[2], 1);
      }
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.ONE, gl.ONE);
      drawInstanced(progs.nebula, nebulae, cam, time);
      drawInstanced(progs.beam, beams, cam, time);
      drawInstanced(progs.particle, particles, cam, time);
      drawInstanced(progs.star, stars, cam, time);
      gl.disable(gl.BLEND);
      if (t) {
        gl.useProgram(progs.bright.p);
        bindTex(0, t.scene.tex, progs.bright, "u_tex");
        fullscreen(progs.bright, t.a, t.a.w, t.a.h);
        gl.useProgram(progs.blur.p);
        bindTex(0, t.a.tex, progs.blur, "u_tex");
        gl.uniform2f(progs.blur.u("u_step"), 1 / t.a.w, 0);
        fullscreen(progs.blur, t.b, t.b.w, t.b.h);
        bindTex(0, t.b.tex, progs.blur, "u_tex");
        gl.uniform2f(progs.blur.u("u_step"), 0, 1 / t.a.h);
        fullscreen(progs.blur, t.a, t.a.w, t.a.h);
        gl.useProgram(progs.composite.p);
        bindTex(0, t.scene.tex, progs.composite, "u_scene");
        bindTex(1, t.a.tex, progs.composite, "u_bloom");
        gl.uniform3f(progs.composite.u("u_background"), BACKGROUND[0], BACKGROUND[1], BACKGROUND[2]);
        fullscreen(progs.composite, null, w, h);
      }
      gl.bindVertexArray(null);
    },
    dispose() {
      canvas.removeEventListener("webglcontextlost", handleLost);
      if (lost || gl.isContextLost()) return;
      for (const inst of [stars, beams, particles, nebulae]) {
        gl.deleteBuffer(inst.buf);
        gl.deleteVertexArray(inst.vao);
      }
      gl.deleteVertexArray(emptyVao);
      for (const pr of Object.values(progs)) gl.deleteProgram(pr.p);
      if (targets) {
        freeTarget(gl, targets.scene);
        freeTarget(gl, targets.a);
        freeTarget(gl, targets.b);
      }
    },
  };
}
