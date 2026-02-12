// ---------- Cute helpers ----------
function toast(title, subtitle = "", emoji = "💖", ms = 2600) {
  const wrap = document.getElementById("toasts");
  if (!wrap) return;

  const t = document.createElement("div");
  t.className = "toast";
  t.innerHTML = `
    <div class="toast-emoji" aria-hidden="true">${emoji}</div>
    <div>
      <div>${escapeHtml(title)}</div>
      ${subtitle ? `<div class="toast-sub">${escapeHtml(subtitle)}</div>` : ""}
    </div>
  `;
  wrap.appendChild(t);

  setTimeout(() => {
    t.style.opacity = "0";
    t.style.transform = "translateY(6px)";
    t.style.transition = "opacity 200ms ease, transform 200ms ease";
    setTimeout(() => t.remove(), 230);
  }, ms);
}

function setStatus(msg, countAll = null) {
  const s = document.getElementById("statusText");
  if (s) s.textContent = msg;
  if (countAll !== null) {
    const b = document.getElementById("countAll");
    if (b) b.textContent = `${countAll} found`;
  }
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// ---------- DOM ----------
const inputText = document.getElementById("inputText");
const btnExtract = document.getElementById("btnExtract");
const btnClear = document.getElementById("btnClear");
const btnSample = document.getElementById("btnSample");
const toggleDefang = document.getElementById("toggleDefang");

const tabs = Array.from(document.querySelectorAll(".tab"));
const lists = {
  urls: document.getElementById("list-urls"),
  domains: document.getElementById("list-domains"),
  ips: document.getElementById("list-ips"),
  hashes: document.getElementById("list-hashes"),
};
const counts = {
  urls: document.getElementById("cUrls"),
  domains: document.getElementById("cDomains"),
  ips: document.getElementById("cIps"),
  hashes: document.getElementById("cHashes"),
};

const emptyState = document.getElementById("emptyState");

const btnCopyTab = document.getElementById("btnCopyTab");
const btnCopyAll = document.getElementById("btnCopyAll");

const btnExport = document.getElementById("btnExport");
const exportMenu = document.getElementById("exportMenu");

const modalBackdrop = document.getElementById("modalBackdrop");
const modalClose = document.getElementById("modalClose");
const modalValue = document.getElementById("modalValue");
const btnCopyOne = document.getElementById("btnCopyOne");
const btnVT = document.getElementById("btnVT");
const btnAIPDB = document.getElementById("btnAIPDB");

// Current state
let currentTab = "urls";
let lastExtracted = { urls: [], domains: [], ips: [], hashes: [] };
let modalCurrentValue = "";

// ---------- IOC extraction patterns ----------
// Notes: These are pragmatic, not perfect. Perfect parsing is a rabbit hole.
const RE = {
  // URL: supports http/https plus common obfuscations (hxxp, hxxps)
  url: /\b(?:https?:\/\/|hxxps?:\/\/)[^\s<>"')\]]+/gi,

  // IPv4
  ip: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,

  // Hashes (MD5, SHA1, SHA256)
  hash: /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/gi,

  // Domain-ish (captures domain.tld patterns). We'll filter to avoid emails + obvious false positives.
  domain: /\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+(?:[a-z]{2,63})\b/gi,
};

// ---------- Defang/refang ----------
function defang(str) {
  return str
    .replaceAll("http://", "hxxp://")
    .replaceAll("https://", "hxxps://")
    .replaceAll(".", "[.]");
}

function refang(str) {
  return str
    .replaceAll("hxxp://", "http://")
    .replaceAll("hxxps://", "https://")
    .replaceAll("[.]", ".");
}

// ---------- Utility ----------
function uniqueSorted(arr) {
  return Array.from(new Set(arr)).sort((a, b) => a.localeCompare(b));
}

function isEmailLikeDomain(text, domain) {
  // If it's part of an email address, skip it for "domain" list.
  // We'll do a simple check: any "@" directly before the domain somewhere.
  const idx = text.toLowerCase().indexOf(domain.toLowerCase());
  if (idx <= 0) return false;
  return text[idx - 1] === "@";
}

function extractAll(text) {
  const raw = String(text || "");
  const lower = raw.toLowerCase();

  // URLs
  const urls = (raw.match(RE.url) || []).map(s => s.trim());

  // IPs
  const ips = (raw.match(RE.ip) || []).map(s => s.trim());

  // Hashes (normalize to lowercase)
  const hashes = (raw.match(RE.hash) || []).map(s => s.toLowerCase().trim());

  // Domains: find candidates, then filter out ones found as part of emails and those already inside URLs
  let domainCandidates = (raw.match(RE.domain) || []).map(s => s.trim());

  // Remove domains that are clearly just TLD fragments in URLs? We'll keep them but dedupe later.
  domainCandidates = domainCandidates.filter(d => !isEmailLikeDomain(raw, d));

  // Extract domains from URLs too (so you always have them)
  const urlDomains = urls.map(u => {
    const clean = refang(u); // ensure parseable
    try {
      const urlObj = new URL(clean);
      return urlObj.hostname;
    } catch {
      return null;
    }
  }).filter(Boolean);

  // Combine and dedupe
  let domains = domainCandidates.concat(urlDomains);

  // Remove "localhost" style stuff not matched anyway; keep basic.
  domains = domains.filter(d => d.includes("."));

  // Normalize domains to lowercase
  domains = domains.map(d => d.toLowerCase());

  return {
    urls: uniqueSorted(urls),
    ips: uniqueSorted(ips),
    hashes: uniqueSorted(hashes),
    domains: uniqueSorted(domains),
  };
}

function applyDefangIfNeeded(data) {
  if (!toggleDefang?.checked) return data;

  return {
    urls: data.urls.map(defang),
    domains: data.domains.map(d => d.replaceAll(".", "[.]")),
    ips: data.ips, // typically not defanged; you can if you want
    hashes: data.hashes, // don't defang hashes
  };
}

function totalCount(data) {
  return data.urls.length + data.domains.length + data.ips.length + data.hashes.length;
}

// ---------- Rendering ----------
function clearLists() {
  Object.values(lists).forEach(ul => (ul.innerHTML = ""));
}

function renderList(kind, values) {
  const ul = lists[kind];
  if (!ul) return;

  ul.innerHTML = "";
  values.forEach(v => {
    const li = document.createElement("li");
    li.className = "ioc-item";
    li.dataset.value = v;
    li.dataset.kind = kind;

    const sub = kind === "urls"
      ? "URL"
      : kind === "domains"
        ? "Domain"
        : kind === "ips"
          ? "IPv4"
          : "Hash";

    // tiny “suspicious vibes” pill (purely heuristic)
    const vibes = getVibes(kind, v);

    li.innerHTML = `
      <div class="ioc-left">
        <div class="ioc-value" title="${escapeHtml(v)}">${escapeHtml(v)}</div>
        <div class="ioc-sub">${sub}${vibes ? ` • ${escapeHtml(vibes)}` : ""}</div>
      </div>
      <div class="ioc-pill">⋯</div>
    `;

    li.addEventListener("click", () => openModal(kind, v));
    ul.appendChild(li);
  });
}

function setCounts(data) {
  counts.urls.textContent = data.urls.length;
  counts.domains.textContent = data.domains.length;
  counts.ips.textContent = data.ips.length;
  counts.hashes.textContent = data.hashes.length;
}

function showEmptyState(shouldShow) {
  if (!emptyState) return;
  emptyState.classList.toggle("show", shouldShow);
}

function setActiveTab(tabName) {
  currentTab = tabName;

  tabs.forEach(t => {
    const isActive = t.dataset.tab === tabName;
    t.classList.toggle("active", isActive);
    t.setAttribute("aria-selected", isActive ? "true" : "false");
  });

  Object.entries(lists).forEach(([k, ul]) => {
    ul.classList.toggle("active", k === tabName);
  });
}

// ---------- Heuristic “vibes” (truthful, not magical) ----------
function getVibes(kind, value) {
  const v = value.toLowerCase();
  if (kind === "urls") {
    if (v.includes("xn--")) return "punycode vibes 😵‍💫";
    if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(refang(v))) return "IP-in-URL 😬";
    if (v.length > 120) return "long link energy 😭";
    if (v.includes("@")) return "userinfo trick 👀";
  }
  if (kind === "domains") {
    if (v.includes("xn--")) return "punycode vibes 😵‍💫";
    if (v.split(".").length >= 4) return "many subdomains 🧅";
  }
  return "";
}

// ---------- Actions ----------
function doExtract() {
  const text = inputText?.value || "";
  const base = extractAll(text);
  const data = applyDefangIfNeeded(base);

  lastExtracted = data;

  // Render
  clearLists();
  renderList("urls", data.urls);
  renderList("domains", data.domains);
  renderList("ips", data.ips);
  renderList("hashes", data.hashes);

  setCounts(data);

  const n = totalCount(data);
  setStatus(
    n ? `Extracted ${n} indicators. You’re basically a SOC wizard now.` : "No indicators found. Peaceful era.",
    n
  );

  showEmptyState(n === 0);

  if (n > 0) {
    toast("Extraction complete!", `${n} spicy little indicators found.`, "✨");
  } else {
    toast("No IOCs found.", "This text is innocent (for now).", "😇");
  }

  // Default tab selection: first non-empty list
  const order = ["urls", "domains", "ips", "hashes"];
  const first = order.find(k => data[k].length > 0) || "urls";
  setActiveTab(first);
}

function doClear() {
  if (inputText) inputText.value = "";
  lastExtracted = { urls: [], domains: [], ips: [], hashes: [] };
  clearLists();
  setCounts(lastExtracted);
  showEmptyState(true);
  setStatus("Cleared. Fresh slate bestie.", 0);
  toast("Cleared!", "We love a clean desk moment.", "🧼");
}

function loadSample() {
  const sample = `
Hey team,

User reported a suspicious email. They clicked:
hxxps://micros0ft-login.example.com/auth?redirect=https%3A%2F%2Flogin.example.com%2F&session=abc123

Attachment: invoice.pdf
SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae

Observed callback domain: cdn-assets.example.net
Possible IPs: 185.193.88.12 and 91.92.93.94

Also seen: http://10.10.10.10/bad (internal example)
FYI: contact: helpdesk@company.com
  `.trim();

  if (inputText) inputText.value = sample;
  toast("Sample loaded!", "Press Extract to see the magic.", "📎");
  setStatus("Sample loaded. Press Extract.", null);
}

// ---------- Copy & Export ----------
async function copyText(str) {
  try {
    await navigator.clipboard.writeText(str);
    return true;
  } catch {
    return false;
  }
}

function getTabData(tab) {
  return lastExtracted[tab] || [];
}

async function copyCurrentTab() {
  const arr = getTabData(currentTab);
  if (!arr.length) return toast("Nothing to copy.", "This tab is empty bestie.", "🫠");
  const ok = await copyText(arr.join("\n"));
  if (ok) toast("Copied!", `Copied ${arr.length} item(s) from ${currentTab}.`, "📋");
  else toast("Copy failed.", "Your browser said no. Try manual copy 😭", "😭");
}

async function copyAll() {
  const lines = [];
  if (lastExtracted.urls.length) lines.push("[URLs]", ...lastExtracted.urls, "");
  if (lastExtracted.domains.length) lines.push("[Domains]", ...lastExtracted.domains, "");
  if (lastExtracted.ips.length) lines.push("[IPs]", ...lastExtracted.ips, "");
  if (lastExtracted.hashes.length) lines.push("[Hashes]", ...lastExtracted.hashes, "");

  if (!lines.length) return toast("Nothing to copy.", "Paste something first!", "🫠");
  const ok = await copyText(lines.join("\n"));
  if (ok) toast("Copied all!", "Go forth and triage 💅", "💅");
  else toast("Copy failed.", "Manual copy time, sorry bestie.", "😭");
}

function exportJSON() {
  const payload = {
    createdAt: new Date().toISOString(),
    defanged: !!toggleDefang?.checked,
    ...lastExtracted
  };
  downloadFile("iocs.json", JSON.stringify(payload, null, 2), "application/json");
  toast("Exported JSON!", "Your indicators are ready.", "🧾");
}

function exportCSV() {
  // columns: type,value
  const rows = [["type", "value"]];

  lastExtracted.urls.forEach(v => rows.push(["url", v]));
  lastExtracted.domains.forEach(v => rows.push(["domain", v]));
  lastExtracted.ips.forEach(v => rows.push(["ip", v]));
  lastExtracted.hashes.forEach(v => rows.push(["hash", v]));

  const csv = rows.map(r => r.map(cell => `"${String(cell).replaceAll('"','""')}"`).join(",")).join("\n");
  downloadFile("iocs.csv", csv, "text/csv");
  toast("Exported CSV!", "Spreadsheet enjoyers rejoice.", "📈");
}

function downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------- Modal (safe lookups) ----------
function openModal(kind, value) {
  modalCurrentValue = value;
  if (modalValue) modalValue.textContent = value;

  // Safe lookup URLs (we use refanged versions for searching)
  const q = encodeURIComponent(refang(value));

  // VirusTotal search: works for URLs/domains/ips/hashes as query
  if (btnVT) btnVT.href = `https://www.virustotal.com/gui/search/${q}`;

  // AbuseIPDB only makes sense for IPs — otherwise we still allow a search for convenience
  if (btnAIPDB) {
    if (kind === "ips") btnAIPDB.href = `https://www.abuseipdb.com/check/${encodeURIComponent(refang(value))}`;
    else btnAIPDB.href = `https://www.abuseipdb.com/`;
  }

  modalBackdrop?.classList.add("show");
  modalBackdrop?.setAttribute("aria-hidden", "false");
}

function closeModal() {
  modalBackdrop?.classList.remove("show");
  modalBackdrop?.setAttribute("aria-hidden", "true");
  modalCurrentValue = "";
}

// ---------- Menu ----------
function toggleExportMenu(forceOpen = null) {
  if (!exportMenu) return;
  const hidden = exportMenu.getAttribute("aria-hidden") === "true" || exportMenu.getAttribute("aria-hidden") === null;
  const open = forceOpen !== null ? forceOpen : hidden;
  exportMenu.setAttribute("aria-hidden", open ? "false" : "true");
  exportMenu.style.display = open ? "block" : "none";
}

// ---------- Events ----------
tabs.forEach(t => {
  t.addEventListener("click", () => setActiveTab(t.dataset.tab));
});

btnExtract?.addEventListener("click", doExtract);
btnClear?.addEventListener("click", doClear);
btnSample?.addEventListener("click", loadSample);

toggleDefang?.addEventListener("change", () => {
  // re-render existing data by re-extracting from input to keep it honest
  toast(toggleDefang.checked ? "Defang ON" : "Defang OFF",
        toggleDefang.checked ? "No accidental clicks today 😇" : "Danger mode (be careful bestie) 😈",
        toggleDefang.checked ? "😇" : "😈");
  doExtract();
});

btnCopyTab?.addEventListener("click", copyCurrentTab);
btnCopyAll?.addEventListener("click", copyAll);

btnExport?.addEventListener("click", (e) => {
  e.stopPropagation();
  toggleExportMenu();
});

document.addEventListener("click", () => toggleExportMenu(false));
exportMenu?.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-export]");
  if (!btn) return;
  const type = btn.getAttribute("data-export");
  toggleExportMenu(false);
  if (type === "json") exportJSON();
  if (type === "csv") exportCSV();
});

modalClose?.addEventListener("click", closeModal);
modalBackdrop?.addEventListener("click", (e) => {
  if (e.target === modalBackdrop) closeModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});

btnCopyOne?.addEventListener("click", async () => {
  if (!modalCurrentValue) return;
  const ok = await copyText(modalCurrentValue);
  if (ok) toast("Copied!", "snatched that indicator, bestie 💅", "💅");
  else toast("Copy failed.", "Manual copy time 😭", "😭");
});

// Init UI
showEmptyState(true);
setStatus("Ready. Paste text and smash “Extract.”", 0);
toggleExportMenu(false);
