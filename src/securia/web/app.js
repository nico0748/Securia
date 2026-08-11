"use strict";

/* Securia ダッシュボード。
   API 呼び出しには起動時トークンを必ず添える。EventSource はカスタム
   ヘッダを送れないため、進捗の受信は fetch のストリームを自前で
   SSE として読む。 */

const TOKEN = document.querySelector('meta[name="securia-token"]').content;
const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_VAR = { CRITICAL: "--crit", HIGH: "--high", MEDIUM: "--med", LOW: "--low", INFO: "--info" };
const CAT_LABEL = { dependency: "依存関係", static: "静的解析", config: "設定" };

const state = {
  data: null,           // 直近のスキャン結果
  target: null,
  suppressed: new Set(),
  jobId: null,
  sevOn: Object.fromEntries(SEV.map(s => [s, true])),
  catOn: { dependency: true, static: true, config: true },
  expanded: new Set(),
};

const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cssVar = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

/* ---------------- API ---------------- */
async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "X-Securia-Token": TOKEN, "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

/* ---------------- 画面遷移 ---------------- */
function showView(name) {
  document.querySelectorAll("#nav button").forEach(b => {
    if (b.dataset.view === name) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  document.querySelectorAll(".view").forEach(v => { v.hidden = v.dataset.view !== name; });

  const isStandalone = name === "history" || name === "suppressions";
  $("gate").hidden = isStandalone || !!state.data;
  $("results").hidden = isStandalone || !state.data;

  if (name === "history") loadHistory();
  if (name === "suppressions") loadSuppressions();
}

document.querySelectorAll("#nav button").forEach(b =>
  b.addEventListener("click", () => showView(b.dataset.view)));

function showGate(which) {
  ["emptyState", "loadingState", "errorState"].forEach(id => { $(id).hidden = id !== which; });
  $("gate").hidden = false;
  $("results").hidden = true;
}

/* ---------------- 起動 ---------------- */
(async function init() {
  try {
    const s = await api("/api/state");
    if (!$("path").value) $("path").value = s.default_path || "";
    if (s.targets && s.targets.length) {
      $("knownTargets").innerHTML = "最近スキャンした対象" +
        `<span class="known-list">${s.targets.slice(0, 6).map(t =>
          `<button type="button" class="chip known" data-target="${esc(t.target)}"
                   title="${esc(t.target)}">${esc(t.target)}</button>`).join("")}</span>`;
      $("knownTargets").querySelectorAll("button.known").forEach(b =>
        b.addEventListener("click", () => {
          $("path").value = b.dataset.target;
          startScan();
        }));
    }
    await refreshSuppressionCount();
  } catch (e) {
    $("errorMsg").textContent = e.message;
    showGate("errorState");
  }
})();

$("scanBtn").addEventListener("click", startScan);
$("cancelBtn").addEventListener("click", cancelScan);
$("path").addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });

/* ---------------- スキャン ---------------- */
async function startScan() {
  const path = $("path").value.trim();
  if (!path) { $("path").focus(); return; }

  setScanning(true);
  showGate("loadingState");
  $("loadingPhase").textContent = "準備中…";
  $("loadingDetail").textContent = path;

  try {
    const job = await api("/api/scans", { method: "POST", body: JSON.stringify({ path }) });
    state.jobId = job.job_id;
    await streamJob(job.job_id);
  } catch (e) {
    $("errorMsg").textContent = e.message;
    showGate("errorState");
    setScanning(false);
  }
}

async function cancelScan() {
  if (!state.jobId) return;
  try { await api(`/api/jobs/${state.jobId}`, { method: "DELETE" }); } catch { /* 既に終了 */ }
}

function setScanning(on) {
  $("scanBtn").disabled = on;
  $("cancelBtn").hidden = !on;
  $("progressBar").hidden = !on;
  $("topStatus").textContent = on ? "スキャン中…" : "";
  if (!on) state.jobId = null;
}

function setProgress(current, total) {
  const bar = $("progressBar");
  const fill = bar.querySelector("i");
  if (total > 0) {
    bar.classList.remove("indeterminate");
    fill.style.width = `${Math.min(100, (current / total) * 100)}%`;
  } else {
    bar.classList.add("indeterminate");
    fill.style.width = "30%";
  }
}

/* SSE を fetch で読む。EventSource だとトークンヘッダを付けられない。 */
async function streamJob(jobId) {
  const res = await fetch(`/api/jobs/${jobId}/events`, { headers: { "X-Securia-Token": TOKEN } });
  if (!res.ok || !res.body) throw new Error("進捗を購読できませんでした");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let sep;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      const line = frame.split("\n").find(l => l.startsWith("data: "));
      if (!line) continue;
      let event;
      try { event = JSON.parse(line.slice(6)); } catch { continue; }
      if (await handleEvent(event, jobId)) return;
    }
  }
  // ストリームが終わったのに終了イベントを受け取れていない場合の保険
  await finishJob(jobId);
}

async function handleEvent(event, jobId) {
  switch (event.type) {
    case "state":
      $("loadingPhase").textContent = event.phase || "スキャン中…";
      setProgress(event.current, event.total);
      if (event.state !== "running") { await finishJob(jobId); return true; }
      return false;
    case "progress":
      $("loadingPhase").textContent = event.phase;
      $("loadingDetail").textContent = event.total > 0
        ? `${event.current} / ${event.total}` : (event.current ? `${event.current} 件` : "");
      setProgress(event.current, event.total);
      return false;
    case "done":
    case "cancelled":
    case "error":
      await finishJob(jobId);
      return true;
    default:
      return false;
  }
}

async function finishJob(jobId) {
  setScanning(false);
  let job;
  try { job = await api(`/api/jobs/${jobId}`); }
  catch (e) { $("errorMsg").textContent = e.message; showGate("errorState"); return; }

  if (job.state === "done" && job.result) {
    applyResult(job.result);
  } else if (job.state === "cancelled") {
    $("errorMsg").textContent = "スキャンを中断しました。";
    showGate("errorState");
  } else {
    $("errorMsg").textContent = job.error || "スキャンに失敗しました。";
    showGate("errorState");
  }
}

/* ---------------- 結果の適用 ---------------- */
function applyResult(result) {
  state.data = result;
  state.target = result.target;
  state.suppressed = new Set(result.suppressed_fingerprints || []);
  state.expanded.clear();
  $("gate").hidden = true;
  $("results").hidden = false;
  $("topStatus").textContent = "完了 · " + formatTime(result.scanned_at);
  showView("dashboard");
  render();
  refreshSuppressionCount();
}

function formatTime(iso) {
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString("ja-JP", { dateStyle: "short", timeStyle: "short" });
}

function render() {
  const d = state.data;
  const s = d.summary;

  $("c-findings").textContent = s.total_findings;
  $("c-sbom").textContent = s.total_components;
  $("c-static").textContent = s.category_counts.static || 0;
  $("c-config").textContent = s.category_counts.config || 0;
  $("foot").textContent = "対象: " + d.target;

  renderOsvBanner(d.osv_status);
  renderDiff(d.diff);

  $("dashSub").textContent = `${d.target} ／ ${formatTime(d.scanned_at)} にスキャン`;
  $("s-files").textContent = s.total_files;
  $("s-comps").textContent = s.total_components;
  $("s-eco").textContent = Object.entries(s.ecosystems).map(([k, v]) => `${k} ${v}`).join(" · ") || "依存なし";
  $("s-vulncomp").textContent = s.vulnerable_components;
  $("s-total").textContent = s.total_findings;
  $("s-elapsed").textContent = `${d.elapsed_sec} 秒で完了`;

  renderSeverityCards(s.severity_counts);
  renderDistribution(s.severity_counts, s.total_findings);
  renderEcosystems(s);
  renderTopFindings();
  buildFilters();
  renderFindings();
  renderSbom();
  renderCategory("static");
  renderCategory("config");
}

function renderOsvBanner(status) {
  const el = $("osvBanner");
  if (status === "offline") {
    el.hidden = false;
    el.className = "banner warn";
    el.innerHTML = "<span>ⓘ</span><span>OSV データベースに接続できなかったため、依存関係の既知脆弱性 (CVE) 照合はスキップされました。SBOM 一覧は取得済みです。</span>";
  } else if (status === "disabled") {
    el.hidden = false;
    el.className = "banner info";
    el.innerHTML = "<span>ⓘ</span><span>OSV 照合は無効化されています（<code>securia.toml</code> の <code>[osv] enabled</code>）。SBOM のみ表示しています。</span>";
  } else {
    el.hidden = true;
  }
}

function renderDiff(diff) {
  const el = $("diffRow");
  if (!diff || !diff.has_baseline) {
    el.innerHTML = '<span class="diff-pill muted">初回スキャン（比較対象なし）</span>';
    return;
  }
  el.innerHTML = [
    diff.new_count > 0
      ? `<span class="diff-pill new">🆕 新規 ${diff.new_count} 件</span>`
      : `<span class="diff-pill">新規 0 件</span>`,
    diff.fixed_count > 0
      ? `<span class="diff-pill fixed">✅ 修正済み ${diff.fixed_count} 件</span>`
      : "",
    `<span class="diff-pill muted">継続 ${diff.existing_count} 件</span>`,
  ].filter(Boolean).join("");
}

function renderSeverityCards(counts) {
  const max = Math.max(1, ...SEV.map(k => counts[k] || 0));
  $("sevRow").innerHTML = SEV.map(k => `
    <div class="sev-card">
      <div class="top"><span class="dot ${k}"></span>${k}</div>
      <div class="n" style="color:var(${SEV_VAR[k]})">${counts[k] || 0}</div>
      <div class="bar"><i style="width:${((counts[k] || 0) / max) * 100}%;background:var(${SEV_VAR[k]})"></i></div>
    </div>`).join("");
}

function renderDistribution(counts, total) {
  const denom = total || 1;
  const present = SEV.filter(k => (counts[k] || 0) > 0);
  $("distbar").innerHTML = present.length
    ? present.map(k => `<div style="background:var(${SEV_VAR[k]});flex:${counts[k]}" title="${k}: ${counts[k]}">${
        counts[k] / denom > 0.06 ? counts[k] : ""}</div>`).join("")
    : '<div style="background:var(--info);flex:1;color:#fff">検出なし</div>';
  $("distLegend").innerHTML = SEV.map(k =>
    `<span><i style="background:var(${SEV_VAR[k]})"></i>${k} <b>${counts[k] || 0}</b> (${
      Math.round(((counts[k] || 0) / denom) * 100)}%)</span>`).join("");
}

function renderEcosystems(s) {
  const entries = Object.entries(s.ecosystems);
  $("ecoChips").innerHTML = entries.length
    ? entries.map(([k, v]) => `<span class="chip">${esc(k)} <b>${v}</b></span>`).join("") +
      `<span class="chip">脆弱な依存 <b style="color:var(--high)">${s.vulnerable_components}</b></span>`
    : '<span class="muted">依存関係マニフェストは見つかりませんでした。</span>';
}

/* ---------------- 検出の描画 ---------------- */
function visibleFindings() {
  return state.data.findings.filter(f => !f.suppressed || $("fShowSuppressed").checked);
}

function locationHtml(f) {
  if (f.category === "dependency" && f.package) {
    return `${esc(f.package)} @ ${esc(f.version)}<br><span class="muted">${esc(f.file)}</span>`;
  }
  return esc(f.file) + (f.line ? `:${f.line}` : "");
}

function renderTopFindings() {
  const rows = state.data.findings.filter(f => !f.suppressed).slice(0, 10);
  $("topFindings").innerHTML = rows.map(f => `
    <tr>
      <td><span class="badge ${f.severity}">${f.severity}</span></td>
      <td><span class="cat-tag">${CAT_LABEL[f.category]}</span></td>
      <td><div class="fx-title">${esc(f.title)}${f.status === "new" ? ' <span class="badge new">NEW</span>' : ""}</div>
          ${f.description ? `<div class="fx-desc">${esc(f.description)}</div>` : ""}</td>
      <td class="loc">${locationHtml(f)}</td>
    </tr>`).join("") || '<tr class="empty-row"><td colspan="4">検出はありませんでした 🎉</td></tr>';
}

function findingRow(f, showCategory) {
  const isOpen = state.expanded.has(f.uid);
  const cols = showCategory ? 5 : 4;
  const main = `
    <tr class="row ${f.suppressed ? "suppressed" : ""}" data-uid="${esc(f.uid)}">
      <td><span class="badge ${f.severity}">${f.severity}</span></td>
      ${showCategory ? `<td><span class="cat-tag">${CAT_LABEL[f.category]}</span></td>` : ""}
      <td>
        <div class="fx-title">${esc(f.title)}${f.status === "new" ? ' <span class="badge new">NEW</span>' : ""}</div>
        ${f.description ? `<div class="fx-desc">${esc(f.description)}</div>` : ""}
        ${f.recommendation ? `<div class="fx-rec">${esc(f.recommendation)}</div>` : ""}
      </td>
      <td class="loc">${locationHtml(f)}</td>
      <td>
        <button class="btn tiny ghost" data-action="${f.suppressed ? "unsuppress" : "suppress"}"
                data-fp="${esc(f.fingerprint)}">${f.suppressed ? "解除" : "抑制"}</button>
      </td>
    </tr>`;
  if (!isOpen) return main;
  return main + `
    <tr class="detail"><td colspan="${cols}">
      <div id="snippet-${esc(f.uid)}"></div>
      <div class="detail-meta">
        <span>ルール: <code>${esc(f.rule_id)}</code></span>
        <span>fingerprint: <code>${esc(f.fingerprint)}</code></span>
        ${f.fixed_version ? `<span>修正版: <code>${esc(f.fixed_version)}</code></span>` : ""}
      </div>
      ${(f.references || []).length
        ? `<div style="margin-top:8px">${f.references.map(u =>
            `<a class="ref" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a>`).join("")}</div>`
        : ""}
    </td></tr>`;
}

function renderFindings() {
  const q = $("fSearch").value.trim().toLowerCase();
  const newOnly = $("fNewOnly").checked;
  const rows = visibleFindings().filter(f =>
    state.sevOn[f.severity] && state.catOn[f.category] &&
    (!newOnly || f.status === "new") &&
    (!q || `${f.title}${f.file}${f.package}${f.description}${f.rule_id}`.toLowerCase().includes(q)));

  $("findingsBody").innerHTML = rows.map(f => findingRow(f, true)).join("")
    || '<tr class="empty-row"><td colspan="5">条件に一致する検出はありません。</td></tr>';
  hydrateOpenSnippets(rows);
}

function renderCategory(cat) {
  const rows = visibleFindings().filter(f => f.category === cat);
  $(cat + "Body").innerHTML = rows.map(f => findingRow(f, false)).join("")
    || `<tr class="empty-row"><td colspan="4">${
        cat === "static" ? "コードの問題は検出されませんでした 🎉" : "設定の問題は検出されませんでした 🎉"}</td></tr>`;
  hydrateOpenSnippets(rows);
}

function hydrateOpenSnippets(rows) {
  rows.filter(f => state.expanded.has(f.uid) && f.line > 0 && f.file).forEach(loadSnippet);
}

async function loadSnippet(f) {
  const holder = $(`snippet-${f.uid}`);
  if (!holder || holder.dataset.loaded) return;
  holder.dataset.loaded = "1";
  try {
    const params = new URLSearchParams({ target: state.target, file: f.file, line: String(f.line) });
    const res = await api("/api/snippet?" + params.toString());
    if (!res.lines.length) return;
    holder.innerHTML = `<pre class="snippet">${res.lines.map(l =>
      `<div class="ln ${l.target ? "target" : ""}"><span class="no">${l.line}</span><span>${esc(l.text)}</span></div>`
    ).join("")}</pre>`;
  } catch {
    holder.innerHTML = '<p class="muted" style="margin:8px 0 0">該当箇所を読み込めませんでした。</p>';
  }
}

/* 行クリックで詳細を開閉、ボタンで抑制 */
document.addEventListener("click", async e => {
  const button = e.target.closest("button[data-action]");
  if (button) {
    e.stopPropagation();
    const fp = button.dataset.fp;
    if (button.dataset.action === "suppress") await suppress(fp);
    else await unsuppress(fp);
    return;
  }
  const row = e.target.closest("tr.row[data-uid]");
  if (row) {
    const uid = row.dataset.uid;
    if (state.expanded.has(uid)) state.expanded.delete(uid);
    else state.expanded.add(uid);
    renderFindings();
    renderCategory("static");
    renderCategory("config");
  }
});

["fSearch"].forEach(id => $(id).addEventListener("input", renderFindings));
["fNewOnly", "fShowSuppressed"].forEach(id => $(id).addEventListener("change", () => {
  renderFindings(); renderCategory("static"); renderCategory("config");
}));
$("sbomSearch").addEventListener("input", renderSbom);
$("sbomVulnOnly").addEventListener("change", renderSbom);

function buildFilters() {
  $("sevFilters").innerHTML = SEV.map(k =>
    `<button class="fbtn" aria-pressed="${state.sevOn[k]}" data-sev="${k}">
       <i style="background:var(${SEV_VAR[k]})"></i>${k}</button>`).join("");
  $("catFilters").innerHTML = Object.keys(state.catOn).map(k =>
    `<button class="fbtn" aria-pressed="${state.catOn[k]}" data-cat="${k}">${CAT_LABEL[k]}</button>`).join("");

  $("sevFilters").querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
    state.sevOn[b.dataset.sev] = !state.sevOn[b.dataset.sev];
    b.setAttribute("aria-pressed", String(state.sevOn[b.dataset.sev]));
    renderFindings();
  }));
  $("catFilters").querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
    state.catOn[b.dataset.cat] = !state.catOn[b.dataset.cat];
    b.setAttribute("aria-pressed", String(state.catOn[b.dataset.cat]));
    renderFindings();
  }));
}

function renderSbom() {
  const q = $("sbomSearch").value.trim().toLowerCase();
  const vulnOnly = $("sbomVulnOnly").checked;
  const rows = state.data.components.filter(c =>
    (!q || c.name.toLowerCase().includes(q)) && (!vulnOnly || c.vuln_count > 0));

  $("sbomBody").innerHTML = rows.map(c => `
    <tr>
      <td class="fx-title">${esc(c.name)}</td>
      <td class="loc">${esc(c.version)}</td>
      <td><span class="cat-tag">${esc(c.ecosystem)}</span></td>
      <td><span class="muted">${c.scope === "dev" ? "dev" : "runtime"}</span></td>
      <td>${c.vuln_count > 0
            ? `<span class="badge ${c.max_severity}">${c.vuln_count} 件</span>`
            : '<span class="muted">なし</span>'}</td>
      <td class="loc">${esc(c.file)}</td>
    </tr>`).join("") || '<tr class="empty-row"><td colspan="6">依存コンポーネントは見つかりませんでした。</td></tr>';
}

/* ---------------- 抑制 ---------------- */
async function suppress(fingerprint) {
  const f = state.data?.findings.find(x => x.fingerprint === fingerprint);
  const reason = window.prompt("抑制する理由（任意）", "") ?? "";
  await api("/api/suppressions", {
    method: "POST",
    body: JSON.stringify({
      target: state.target, fingerprint, reason,
      rule_id: f?.rule_id || "", file: f?.file || "", title: f?.title || "",
    }),
  });
  state.suppressed.add(fingerprint);
  markSuppressed(fingerprint, true);
}

async function unsuppress(fingerprint) {
  const params = new URLSearchParams({ target: state.target });
  await api(`/api/suppressions/${encodeURIComponent(fingerprint)}?${params}`, { method: "DELETE" });
  state.suppressed.delete(fingerprint);
  markSuppressed(fingerprint, false);
}

/* 抑制は次回スキャンから集計に反映される。今の画面では見た目だけ即座に更新する。 */
function markSuppressed(fingerprint, value) {
  if (state.data) {
    state.data.findings.forEach(f => { if (f.fingerprint === fingerprint) f.suppressed = value; });
  }
  renderFindings();
  renderCategory("static");
  renderCategory("config");
  refreshSuppressionCount();
  loadSuppressions();
}

async function refreshSuppressionCount() {
  try {
    const params = state.target ? "?" + new URLSearchParams({ target: state.target }) : "";
    const res = await api("/api/suppressions" + params);
    $("c-sup").textContent = res.suppressions.length;
  } catch { /* 表示だけの情報なので握りつぶす */ }
}

async function loadSuppressions() {
  try {
    const params = state.target ? "?" + new URLSearchParams({ target: state.target }) : "";
    const res = await api("/api/suppressions" + params);
    $("supBody").innerHTML = res.suppressions.map(s => `
      <tr>
        <td class="loc">${esc(s.fingerprint)}</td>
        <td class="loc">${esc(s.rule_id || "—")}</td>
        <td>${esc(s.file || "—")}${s.reason ? `<div class="fx-desc">${esc(s.reason)}</div>` : ""}</td>
        <td><button class="btn tiny ghost" data-action="unsuppress" data-fp="${esc(s.fingerprint)}">解除</button></td>
      </tr>`).join("") || '<tr class="empty-row"><td colspan="4">抑制した検出はありません。</td></tr>';
  } catch (e) {
    $("supBody").innerHTML = `<tr class="empty-row"><td colspan="4">${esc(e.message)}</td></tr>`;
  }
}

/* ---------------- 履歴 ---------------- */
async function loadHistory() {
  try {
    const res = await api("/api/scans?limit=100");
    $("historyBody").innerHTML = res.scans.map(s => `
      <tr class="row" data-scan="${s.id}">
        <td class="loc">${s.id}</td>
        <td>${esc(formatTime(s.scanned_at))}</td>
        <td><b>${s.summary.total_findings}</b></td>
        <td>${s.summary.severity_counts.CRITICAL || 0}</td>
        <td>${s.summary.severity_counts.HIGH || 0}</td>
        <td class="loc">${esc(s.target)}</td>
      </tr>`).join("") || '<tr class="empty-row"><td colspan="6">履歴はまだありません。</td></tr>';

    $("historyBody").querySelectorAll("tr[data-scan]").forEach(tr =>
      tr.addEventListener("click", () => loadScan(tr.dataset.scan)));
  } catch (e) {
    $("historyBody").innerHTML = `<tr class="empty-row"><td colspan="6">${esc(e.message)}</td></tr>`;
  }
}

async function loadScan(scanId) {
  try {
    const scan = await api(`/api/scans/${scanId}`);
    applyResult({
      target: scan.target,
      scanned_at: scan.scanned_at,
      elapsed_sec: scan.elapsed_sec,
      osv_status: scan.osv_status,
      summary: scan.summary,
      findings: scan.findings,
      components: scan.components,
      suppressed_fingerprints: scan.suppressed_fingerprints,
      diff: null,
    });
  } catch (e) {
    $("errorMsg").textContent = e.message;
    showGate("errorState");
  }
}
