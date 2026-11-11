/* LogSentry dashboard.
 * Live mode: polls the LogSentry API every few seconds.
 * Demo mode: when no API is reachable (e.g. hosted on GitHub Pages), it loads
 * a recorded snapshot from demo-data.json instead.
 * All log content is attacker-controlled, so everything is HTML-escaped. */
(() => {
  "use strict";

  const POLL_MS = 3000;
  const SEV_ORDER = ["critical", "high", "medium", "low"];
  const $ = (id) => document.getElementById(id);

  const state = { mode: null, data: null, filter: "", search: "", open: new Set(), seen: new Set(), first: true };

  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtNum = (n) => (n == null ? "–" : Number(n).toLocaleString("en-US"));
  const fmtTime = (iso) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  const fmtLatency = (ms) => (ms == null ? "–" : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`);
  const mitreUrl = (t) => `https://attack.mitre.org/techniques/${String(t).replace(".", "/")}/`;

  // ---------------------------------------------------------------- data
  async function load() {
    if (state.mode !== "demo") {
      try {
        const res = await fetch("api/dashboard?limit=150", { cache: "no-store" });
        if (res.ok && (res.headers.get("content-type") || "").includes("json")) {
          state.mode = "live";
          return res.json();
        }
      } catch (_) { /* no API here: fall through to demo data */ }
      if (state.mode === "live") throw new Error("API unreachable");
    }
    const res = await fetch("demo-data.json", { cache: "no-store" });
    if (!res.ok) throw new Error("no data source");
    state.mode = "demo";
    return res.json();
  }

  async function refresh() {
    try {
      state.data = await load();
      render();
    } catch (err) {
      setPill("down", "offline");
    }
    if (state.mode !== "demo") setTimeout(refresh, POLL_MS);
  }

  // ---------------------------------------------------------------- render
  function setPill(kind, text) {
    $("mode-pill").className = `pill ${kind}`;
    $("mode-text").textContent = text;
  }

  function render() {
    const d = state.data;
    const s = d.stats;
    if (state.mode === "demo") {
      setPill("demo", "demo snapshot");
      $("demo-banner").hidden = false;
      const when = new Date(d.captured_at);
      $("demo-text").textContent = `Recorded ${when.toLocaleString([], { dateStyle: "medium", timeStyle: "short" })} from a live run of the attack simulator (${s.hosts.length} hosts, ~25 minutes).`;
      $("updated").textContent = "";
    } else {
      setPill("live", d.mode === "demo" ? "live · simulated" : "live");
      $("updated").textContent = `updated ${fmtTime(s.generated_at)}`;
    }
    $("hosts").textContent = `${s.hosts.length} host${s.hosts.length === 1 ? "" : "s"} monitored`;

    $("k-events").textContent = fmtNum(s.total_events);
    $("k-lines").textContent = d.lines_seen != null ? `${fmtNum(d.lines_seen)} log lines read` : "";
    $("k-alerts").textContent = fmtNum(s.total_alerts);
    $("k-open").textContent = `${fmtNum(s.open_alerts)} open`;
    $("k-critical").textContent = fmtNum(s.alerts_by_severity.critical);
    $("k-ips").textContent = fmtNum(s.unique_attackers);
    $("k-latency").textContent = fmtLatency(s.avg_latency_ms);
    $("k-latency-max").textContent = s.max_latency_ms != null ? `mean · max ${fmtLatency(s.max_latency_ms)}` : "log line → alert";

    renderTimeline(s.timeline);
    renderSeverity(s.alerts_by_severity, s.total_alerts);
    renderRules(s.alerts_by_rule);
    renderAttackers(s.top_attackers);
    renderAlerts(d.alerts);
    renderCoverage(d.rules || []);
    state.first = false;
  }

  function renderTimeline(points) {
    const el = $("timeline");
    const W = Math.max(el.clientWidth, 300), H = el.clientHeight || 210;
    const pad = { l: 34, r: 8, t: 10, b: 22 };
    const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
    const max = Math.max(5, ...points.map((p) => p.events));
    const nice = Math.pow(10, Math.floor(Math.log10(max)));
    const top = Math.ceil(max / nice) * nice;
    const bw = iw / points.length;
    const y = (v) => pad.t + ih - (v / top) * ih;

    let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Events and alerts per minute">`;
    for (let i = 0; i <= 4; i++) {
      const v = (top / 4) * i, yy = y(v);
      svg += `<line class="grid-line" x1="${pad.l}" x2="${W - pad.r}" y1="${yy}" y2="${yy}"/>`;
      svg += `<text class="axis" x="${pad.l - 6}" y="${yy + 3}" text-anchor="end">${Math.round(v)}</text>`;
    }
    points.forEach((p, i) => {
      const x = pad.l + i * bw, h = (p.events / top) * ih;
      svg += `<rect class="ev-bar" x="${x + 1}" y="${pad.t + ih - h}" width="${Math.max(bw - 2, 1)}" height="${h}" rx="1.5"><title>${esc(p.t.slice(11))} UTC · ${p.events} events · ${p.alerts} alerts</title></rect>`;
      if (p.alerts > 0) {
        const r = Math.min(3 + p.alerts * 1.2, 8);
        svg += `<circle class="al-dot" cx="${x + bw / 2}" cy="${y(p.events) - r - 3}" r="${r}"><title>${p.alerts} alert(s)</title></circle>`;
      }
      if (i % Math.ceil(points.length / 6) === 0) {
        svg += `<text class="axis" x="${x + bw / 2}" y="${H - 6}" text-anchor="middle">${esc(localMinute(p.t))}</text>`;
      }
    });
    el.innerHTML = svg + "</svg>";
  }

  const localMinute = (t) => fmtTime(t + ":00Z").slice(0, 5);

  function renderSeverity(by, total) {
    const stack = SEV_ORDER.filter((k) => by[k] > 0)
      .map((k) => `<span class="bg-${k}" style="flex:${by[k]}" title="${k}: ${by[k]}"></span>`).join("");
    const items = SEV_ORDER.map((k) => `
      <div class="sev-item"><div class="t"><i class="dot bg-${k}"></i>${k}</div>
      <div class="n">${fmtNum(by[k])}</div></div>`).join("");
    $("severity").innerHTML = `<div class="stack">${stack || '<span style="flex:1"></span>'}</div><div class="sev-list">${items}</div>
      <div class="meta">${fmtNum(total)} alerts total</div>`;
  }

  function renderRules(rows) {
    const max = Math.max(1, ...rows.map((r) => r.n));
    $("by-rule").innerHTML = rows.length ? rows.map((r) => `
      <div class="bar-row"><span class="name" title="${esc(r.title)}">${esc(r.title)}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${(r.n / max) * 100}%;display:block"></span></span>
      <span class="n">${r.n}</span></div>`).join("") : `<p class="empty">No detections yet.</p>`;
  }

  function renderAttackers(rows) {
    const sev = ["low", "medium", "high", "critical"];
    $("attackers").querySelector("tbody").innerHTML = rows.length ? rows.map((r) => `
      <tr><td class="ip">${esc(r.ip)}</td><td><span class="sev ${sev[r.worst]}">${sev[r.worst]}</span></td>
      <td class="num">${r.alerts}</td><td class="num">${fmtNum(r.events)}</td></tr>`).join("")
      : `<tr><td colspan="4" class="empty">No attackers yet.</td></tr>`;
  }

  function renderAlerts(alerts) {
    const q = state.search.toLowerCase();
    const list = alerts.filter((a) => (!state.filter || a.severity === state.filter) &&
      (!q || [a.title, a.src_ip, a.host, a.user, a.rule_id, a.mitre, a.description].join(" ").toLowerCase().includes(q)));
    $("empty").hidden = list.length > 0;
    $("alerts").innerHTML = list.map((a) => {
      const fresh = !state.first && !state.seen.has(a.id);
      return `<li data-id="${esc(a.id)}" class="${state.open.has(a.id) ? "open" : ""} ${fresh ? "fresh" : ""}">
        <button class="alert-row" aria-expanded="${state.open.has(a.id)}">
          <span class="time" title="${esc(a.detected_at)}">${fmtTime(a.detected_at)}</span>
          <span class="sevc"><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span></span>
          <span class="title">${esc(a.title)}${a.count > 1 ? `<small>×${a.count}</small>` : ""}${a.status && a.status !== "open" ? `<span class="status-tag">${esc(a.status.replace("_", " "))}</span>` : ""}</span>
          <span class="ip">${esc(a.src_ip || a.user || "–")}</span>
          <span class="host">${esc(a.host || "–")}</span>
          <span class="mitre">${esc(a.mitre)}</span>
        </button>
        <div class="detail">
          <p>${esc(a.description)}</p>
          <div class="facts">
            <span>rule <b>${esc(a.rule_id)}</b></span>
            <span>detected in <b>${fmtLatency(a.latency_ms)}</b></span>
            ${a.mitre ? `<span>ATT&amp;CK <a href="${esc(mitreUrl(a.mitre))}" target="_blank" rel="noopener">${esc(a.mitre)}</a></span>` : ""}
            ${a.user ? `<span>user <b>${esc(a.user)}</b></span>` : ""}
          </div>
          <pre class="evidence">${(a.evidence || []).map(esc).join("\n")}</pre>
          ${state.mode === "live" ? `<div class="actions">
            <button data-status="acknowledged">Acknowledge</button><button data-status="resolved">Resolve</button>
            <button data-status="false_positive">False positive</button></div>` : ""}
        </div></li>`;
    }).join("");
    alerts.forEach((a) => state.seen.add(a.id));
  }

  function renderCoverage(rules) {
    $("rules").innerHTML = rules.map((r) => `
      <li><div class="r-top"><span class="r-name">${esc(r.name)}</span><span class="sev ${esc(r.severity)}">${esc(r.severity)}</span></div>
      <a href="${esc(mitreUrl(r.mitre))}" target="_blank" rel="noopener">${esc(r.mitre)}</a></li>`).join("");
  }

  // ---------------------------------------------------------------- events
  $("alerts").addEventListener("click", async (e) => {
    const li = e.target.closest("li");
    if (!li) return;
    const id = li.dataset.id;
    const statusBtn = e.target.closest("button[data-status]");
    if (statusBtn) {
      const res = await fetch(`api/alerts/${encodeURIComponent(id)}/status`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: statusBtn.dataset.status }),
      });
      if (res.ok) {
        const a = state.data.alerts.find((x) => x.id === id);
        if (a) a.status = statusBtn.dataset.status;
        renderAlerts(state.data.alerts);
      }
      return;
    }
    if (!e.target.closest(".alert-row")) return;
    state.open.has(id) ? state.open.delete(id) : state.open.add(id);
    li.classList.toggle("open");
    li.querySelector(".alert-row").setAttribute("aria-expanded", state.open.has(id));
  });

  $("chips").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    state.filter = b.dataset.sev;
    $("chips").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
    if (state.data) renderAlerts(state.data.alerts);
  });

  $("search").addEventListener("input", (e) => {
    state.search = e.target.value;
    if (state.data) renderAlerts(state.data.alerts);
  });

  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => state.data && renderTimeline(state.data.stats.timeline), 150);
  });

  refresh();
})();
