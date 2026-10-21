const app = document.querySelector("#app");
const toast = document.querySelector("#toast");
let currentUser = null;
let csrf = "";
let documents = [];
let searchTimer;

async function api(path, options = {}) {
  const headers = { ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers };
  if (csrf && ["POST", "PATCH", "DELETE"].includes(options.method)) headers["X-CSRF-Token"] = csrf;
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  if (response.status === 204) return null;
  const type = response.headers.get("content-type") || "";
  const body = type.includes("application/json") ? await response.json() : await response.blob();
  if (!response.ok) throw new Error(body.error || "Request failed");
  return body;
}

function notify(message) {
  toast.textContent = message;
  toast.className = "toast show";
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => { toast.className = "toast"; }, 2800);
}

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
function date(value) { return new Date(value * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }); }
function size(bytes) { return bytes < 1024 * 1024 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`; }
function fileTag(name) { return escapeHtml((name.split(".").pop() || "FILE").slice(0, 4).toUpperCase()); }

function loginScreen(message = "") {
  app.innerHTML = `<div class="login-page"><section class="login-visual">
    <div class="brand"><span class="brand-mark">◈</span>trustvault</div>
    <div class="login-quote"><h1>Your documents.<br>Only the right hands.</h1><p>Confidential files deserve more than a shared link. Give access by person, take it back instantly, and keep a record of every action.</p></div>
    <div class="login-caption">PRIVATE BY DEFAULT · ACCOUNTABLE BY DESIGN</div></section>
    <section class="login-side"><form class="login-card" id="login-form"><div class="eyebrow">SECURE WORKSPACE</div><h2>Welcome back</h2><p>Sign in to your TrustVault account.</p>
    ${message ? `<p role="alert" style="color:#a43d36">${escapeHtml(message)}</p>` : ""}
    <div class="field"><label for="email">Work email</label><input class="input" id="email" name="email" type="email" autocomplete="username" required placeholder="you@company.com"></div>
    <div class="field"><label for="password">Password</label><input class="input" id="password" name="password" type="password" autocomplete="current-password" required></div>
    <button class="primary" type="submit">Sign in securely</button><div class="login-foot">Your access is checked by the server on every request.</div></form></section></div>`;
  document.querySelector("#login-form").addEventListener("submit", async event => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const result = await api("/api/login", { method: "POST", body: JSON.stringify({ email: form.get("email"), password: form.get("password") }) });
      currentUser = result.user; csrf = result.csrf; await loadWorkspace();
    } catch (error) { loginScreen(error.message); }
  });
}

async function bootstrap() {
  try {
    const result = await api("/api/me");
    currentUser = result.user; csrf = result.csrf; await loadWorkspace();
  } catch { loginScreen(); }
}

async function loadWorkspace(filters = "") {
  if (currentUser.role === "admin") return renderAdmin();
  const result = await api(`/api/documents${filters ? `?${filters}` : ""}`);
  documents = result.documents;
  renderDocuments();
}

function renderDocuments() {
  const isOwner = currentUser.role === "owner";
  const name = escapeHtml(currentUser.name.split(" ")[0]);
  const rows = documents.map(doc => `<tr><td><div class="file-cell"><span class="file-icon">${fileTag(doc.name)}</span><div><div class="file-name">${escapeHtml(doc.name)}</div><div class="file-meta">${size(doc.size)} · ${escapeHtml(doc.owner.name)}</div></div></div></td>
    <td><span class="category">${escapeHtml(doc.category)}</span></td><td>${date(doc.updated_at)}</td><td><span class="permission">${doc.permission === "owner" ? "Owner" : `${escapeHtml(doc.permission)} access`}</span></td>
    <td><div class="actions"><button class="icon-button" title="Download" aria-label="Download ${escapeHtml(doc.name)}" data-download="${doc.id}">↓</button>${doc.permission === "owner" ? `<button class="icon-button" title="Manage access" aria-label="Manage access to ${escapeHtml(doc.name)}" data-share="${doc.id}">♧</button><button class="icon-button" title="Edit details" aria-label="Edit ${escapeHtml(doc.name)}" data-edit="${doc.id}">✎</button><button class="icon-button" title="Delete" aria-label="Delete ${escapeHtml(doc.name)}" data-delete="${doc.id}">×</button>` : ""}</div></td></tr>`).join("");
  app.innerHTML = `<div class="shell"><header class="topbar"><div class="brand"><span class="brand-mark">◈</span>trustvault</div><div class="user-menu"><span class="avatar">${escapeHtml(currentUser.name.split(" ").map(part => part[0]).join("").slice(0, 2))}</span><div class="user-copy"><div class="user-name">${escapeHtml(currentUser.name)}</div><div class="user-role">${escapeHtml(currentUser.role)}</div></div><button class="logout" id="logout">Sign out</button></div></header>
  <section class="header-row"><div><div class="eyebrow">YOUR PRIVATE WORKSPACE</div><h1 class="heading">Good morning, ${name}</h1><p class="subheading">${isOwner ? "Your documents, and the people you choose to share them with." : "Documents that have been shared with you."}</p></div>${isOwner ? '<button class="primary" id="upload">＋ &nbsp;Upload document</button>' : ""}</section>
  <div class="toolbar"><label class="search-wrap"><input class="input" id="search" placeholder="Search documents by name…" aria-label="Search by name"></label><input class="input" id="owner-filter" placeholder="Owner email" aria-label="Filter by owner"><input class="input date" id="after" type="date" aria-label="From date"><input class="input date" id="before" type="date" aria-label="To date"><select class="select" id="category"><option value="">All categories</option>${[...new Set(documents.map(d => d.category))].map(c => `<option>${escapeHtml(c)}</option>`).join("")}</select></div>
  <div class="section-head"><div><span class="section-title">Documents</span><span class="count">${documents.length} files</span></div></div>
  <section class="table-card">${documents.length ? `<table class="table"><thead><tr><th>Document</th><th>Category</th><th>Last updated</th><th>Your access</th><th></th></tr></thead><tbody>${rows}</tbody></table>` : '<div class="empty"><strong>No documents yet</strong>Upload a file or wait for someone to share one with you.</div>'}</section></div>`;
  document.querySelector("#logout").onclick = logout;
  if (isOwner) document.querySelector("#upload").onclick = uploadDialog;
  app.querySelectorAll("[data-download]").forEach(button => button.onclick = () => downloadDoc(button.dataset.download));
  app.querySelectorAll("[data-share]").forEach(button => button.onclick = () => shareDialog(button.dataset.share));
  app.querySelectorAll("[data-edit]").forEach(button => button.onclick = () => editDialog(button.dataset.edit));
  app.querySelectorAll("[data-delete]").forEach(button => button.onclick = () => deleteDoc(button.dataset.delete));
  const filter = () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      const query = new URLSearchParams();
      [["name", "#search"], ["owner", "#owner-filter"], ["after", "#after"], ["before", "#before"], ["category", "#category"]].forEach(([key, selector]) => {
        const value = document.querySelector(selector).value;
        if (value) query.set(key, value);
      });
      loadWorkspace(query.toString()).catch(error => notify(error.message));
    }, 180);
  };
  ["#search", "#owner-filter", "#after", "#before", "#category"].forEach(selector => document.querySelector(selector).addEventListener("input", filter));
}

async function renderAdmin() {
  const result = await api("/api/audit");
  const rows = result.entries.map(entry => `<tr><td>${date(entry.at)}</td><td>${escapeHtml(entry.actor_email || "System")}</td><td><span class="event-pill">${escapeHtml(entry.action.replaceAll("_", " "))}</span></td><td>${escapeHtml(entry.document_id || "—")}</td><td>${escapeHtml(entry.subject_email || "—")}</td><td>${escapeHtml(entry.details)}</td></tr>`).join("");
  app.innerHTML = `<div class="shell"><header class="topbar"><div class="brand"><span class="brand-mark">◈</span>trustvault</div><div class="user-menu"><span class="avatar">AA</span><div class="user-copy"><div class="user-name">${escapeHtml(currentUser.name)}</div><div class="user-role">Administrator</div></div><button class="logout" id="logout">Sign out</button></div></header>
  <div class="eyebrow">ADMINISTRATION</div><h1 class="heading">Activity & evidence</h1><p class="subheading">Review security events and permission changes. Administrators do not automatically get document access.</p>
  <div class="admin-banner"><div><strong>Audit-chain integrity</strong><br><span>Each record is HMAC-signed and linked to the previous record.</span></div><span class="integrity ${result.chain_valid ? "" : "invalid"}">${result.chain_valid ? "✓ Verified" : "⚠ Integrity check failed"}</span></div>
  <div class="section-head"><div><span class="section-title">Recent activity</span><span class="count">${result.entries.length} events · latest 500</span></div></div><section class="table-card">${rows ? `<div style="overflow:auto"><table class="table audit-table"><thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Document</th><th>Subject</th><th>Details</th></tr></thead><tbody>${rows}</tbody></table></div>` : '<div class="empty"><strong>No activity recorded</strong>Events appear here as users work.</div>'}</section></div>`;
  document.querySelector("#logout").onclick = logout;
}

async function logout() {
  try { await api("/api/logout", { method: "POST", body: "{}" }); } finally { currentUser = null; csrf = ""; loginScreen(); }
}

async function downloadDoc(id) {
  try {
    const blob = await api(`/api/documents/${id}/download`);
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    const doc = documents.find(item => item.id === id);
    link.download = doc ? doc.name : "document";
    link.click();
    URL.revokeObjectURL(link.href);
  } catch (error) { notify(error.message); }
}

function modal(title, description, content, submitLabel, onSubmit) {
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.innerHTML = `<form class="modal"><h2>${title}</h2><p>${description}</p>${content}<div class="modal-actions"><button type="button" class="secondary" data-cancel>Cancel</button><button class="primary" type="submit">${submitLabel}</button></div></form>`;
  document.body.append(backdrop);
  backdrop.querySelector("[data-cancel]").onclick = () => backdrop.remove();
  backdrop.onclick = event => { if (event.target === backdrop) backdrop.remove(); };
  backdrop.querySelector("form").onsubmit = async event => {
    event.preventDefault();
    try { await onSubmit(new FormData(event.currentTarget)); backdrop.remove(); }
    catch (error) { notify(error.message); }
  };
}

function uploadDialog() {
  modal("Upload a document", "Files stay private until you grant someone access. Maximum size: 10 MB.", `<div class="field"><label>Choose file</label><input class="input" name="file" type="file" accept=".pdf,.png,.jpg,.jpeg,.txt,.csv,.docx" required></div><div class="field"><label>Category</label><input class="input" name="category" maxlength="80" value="General" required></div>`, "Upload securely", async form => {
    const file = form.get("file");
    if (!file || file.size > 10 * 1024 * 1024) throw new Error("Choose a file up to 10 MB.");
    const content = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result.split(",")[1]); reader.onerror = () => reject(new Error("Could not read file")); reader.readAsDataURL(file); });
    await api("/api/documents", { method: "POST", body: JSON.stringify({ name: file.name, category: form.get("category"), content_base64: content }) });
    notify("Document uploaded privately."); await loadWorkspace();
  });
}

function shareDialog(id) {
  const doc = documents.find(item => item.id === id);
  const grants = doc.grants.map(grant => `<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #eee"><span><strong>${escapeHtml(grant.name)}</strong><br><small>${escapeHtml(grant.email)} · ${escapeHtml(grant.permission)}</small></span><button type="button" class="danger" data-revoke="${escapeHtml(grant.email)}">Revoke</button></div>`).join("");
  modal(`Share ${escapeHtml(doc.name)}`, "Grant access to a named account. Revocation takes effect on the next request.", `${grants || '<p>No one else has access to this document.</p>'}<div class="field"><label>Account email</label><input class="input" name="email" type="email" placeholder="person@company.com" required></div><div class="field"><label>Permission</label><select class="select" name="permission"><option value="read">Read and download</option><option value="edit">Edit details and download</option></select></div>`, "Grant access", async form => {
    await api(`/api/documents/${id}/grants`, { method: "POST", body: JSON.stringify({ email: form.get("email"), permission: form.get("permission") }) });
    notify("Access granted and recorded."); await loadWorkspace();
  });
  document.querySelectorAll("[data-revoke]").forEach(button => button.onclick = async () => {
    if (!confirm(`Revoke access for ${button.dataset.revoke}?`)) return;
    try { await api(`/api/documents/${id}/grants`, { method: "DELETE", body: JSON.stringify({ email: button.dataset.revoke }) }); notify("Access revoked immediately."); await loadWorkspace(); }
    catch (error) { notify(error.message); }
  });
}

function editDialog(id) {
  const doc = documents.find(item => item.id === id);
  modal("Edit document details", "Changes are recorded in the audit trail.", `<div class="field"><label>Document name</label><input class="input" name="name" maxlength="180" value="${escapeHtml(doc.name)}" required></div><div class="field"><label>Category</label><input class="input" name="category" maxlength="80" value="${escapeHtml(doc.category)}" required></div>`, "Save changes", async form => {
    await api(`/api/documents/${id}`, { method: "PATCH", body: JSON.stringify({ name: form.get("name"), category: form.get("category") }) });
    notify("Document details updated."); await loadWorkspace();
  });
}

async function deleteDoc(id) {
  const doc = documents.find(item => item.id === id);
  if (!confirm(`Delete "${doc.name}"? All access grants will be removed.`)) return;
  try { await api(`/api/documents/${id}`, { method: "DELETE" }); notify("Document deleted."); await loadWorkspace(); }
  catch (error) { notify(error.message); }
}

document.addEventListener("DOMContentLoaded", bootstrap);
