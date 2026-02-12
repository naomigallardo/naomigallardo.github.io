const el = (id) => document.getElementById(id);

const inputUrl = el("inputUrl");
const statusText = el("statusText");
const flagCount = el("flagCount");

const outNormalized = el("outNormalized");
const outDecoded = el("outDecoded");

const bScheme = el("bScheme");
const bHost = el("bHost");
const bPath = el("bPath");
const paramsBody = el("paramsBody");
const flagsList = el("flagsList");

const toggleDefang = el("toggleDefang");

const vtSearch = el("vtSearch");

let lastJson = null;

function toast(title, sub = "") {
  const wrap = el("toasts");
  const t = document.createElement("div");
  t.className = "toast";
  t.innerHTML = `
    <div class="toast-title">${escapeHtml(title)}</div>
    ${sub ? `<div class="toast-sub">${escapeHtml(sub)}</div>` : ""}
  `;
  wrap.appendChild(t);
  setTimeout(() => {
    t.style.opacity = "0";
    t.style.transform = "translateY(6px)";
    t.style.transition = "opacity 200ms ease, transform 200ms ease";
    setTimeout(() => t.remove(), 230);
  }, 2600);
}

function setStatus(msg) {
  statusText.textContent = msg;
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function defangAll(urlStr) {
  return urlStr
    .replaceAll("http://", "hxxp://")
    .replaceAll("https://", "hxxps://")
    .replaceAll(".", "[.]");
}

function refangAll(urlStr) {
  return urlStr
    .replaceAll("hxxp://", "http://")
    .replaceAll("hxxps://", "https://")
    .replaceAll("[.]", ".");
}

function stripWrapperJunk(s) {
  // trims common wrapping punctuation like <> () quotes etc.
  return s.trim().replace(/^["'<(\[]+/, "").replace(/[">')\]]+$/, "");
}

function ensureScheme(s) {
  // If it lacks a scheme, assume https for parsing
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return s;
  return "https://" + s;
}

function safeMultiDecode(s, rounds = 3) {
  let out = s;
  for (let i = 0; i < rounds; i++) {
    try {
      const dec = decodeURIComponent(out);
      if (dec === out) break;
      out = dec;
    } catch {
      break;
    }
  }
  return out;
}

function hostIsIPv4(host) {
  return /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(host);
}

function hasDoubleExtension(path) {
  // very basic: file.ext1.ext2
  return /\.[a-z0-9]{1,6}\.[a-z0-9]{1,6}($|\?)/i.test(path);
}

function countParams(urlObj) {
  let n = 0;
  for (const _ of urlObj.searchParams) n++;
  return n;
}

function buildFlags(urlObj, rawInput, normalized, decoded) {
  const flags = [];

  const host = urlObj.hostname.toLowerCase();
  const full = normalized;

  if (host.includes("xn--")) flags.push("Punycode hostname detected (often used for lookalike domains).");
  if (hostIsIPv4(host)) flags.push("Hostname is an IP address (common in phishing/malware links).");
  if (normalized.length > 140) flags.push("Very long URL (can hide intent in parameters).");
  if (/@/.test(urlObj.username || "") || /@/.test(full.split("://")[1] || "")) {
    flags.push("Contains '@' in the authority part (userinfo trick can mislead).");
  }
  if (countParams(urlObj) >= 6) flags.push("Many query parameters (tracking or hiding payloads).");
  if (/%[0-9a-f]{2}/i.test(rawInput)) flags.push("Percent-encoding present (obfuscation or normal URL encoding).");
  if (hasDoubleExtension(urlObj.pathname)) flags.push("Double file extension pattern in path (can be deceptive).");
  if (decoded.includes("http://") || decoded.includes("https://")) {
    if (decoded !== normalized) flags.push("Decoded content contains nested URL(s) (redirect chain behavior).");
  }

  // light “caption” flag (still truthful)
  if (flags.length === 0) flags.push("No obvious red flags from structure alone (still verify reputation/logs).");

  return flags;
}

function renderParams(urlObj) {
  const rows = [];
  for (const [k, v] of urlObj.searchParams.entries()) {
    rows.push([safeMultiDecode(k), safeMultiDecode(v)]);
  }

  if (!rows.length) {
    paramsBody.innerHTML = `<tr><td class="muted" colspan="2">No query parameters</td></tr>`;
    return;
  }

  paramsBody.innerHTML = rows.map(([k, v]) => `
    <tr>
      <td>${escapeHtml(k)}</td>
      <td style="overflow-wrap:anywhere;">${escapeHtml(v)}</td>
    </tr>
  `).join("");
}

function renderFlags(flags) {
  flagsList.innerHTML = flags.map(f => `<li>${escapeHtml(f)}</li>`).join("");
  const countReal = flags[0]?.startsWith("No obvious red flags") ? 0 : flags.length;
  flagCount.textContent = `${countReal} flags`;
}

function buildJson(urlObj, normalized, decoded, flags) {
  const params = [];
  for (const [k, v] of urlObj.searchParams.entries()) {
    params.push({ key: safeMultiDecode(k), value: safeMultiDecode(v) });
  }

  return {
    createdAt: new Date().toISOString(),
    normalized: toggleDefang.checked ? defangAll(normalized) : normalized,
    decoded: toggleDefang.checked ? defangAll(decoded) : decoded,
    components: {
      scheme: urlObj.protocol.replace(":", ""),
      host: toggleDefang.checked ? urlObj.hostname.replaceAll(".", "[.]") : urlObj.hostname,
      path: urlObj.pathname,
      query: urlObj.search,
      fragment: urlObj.hash || ""
    },
    params,
    flags
  };
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
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

function analyze() {
  const raw = stripWrapperJunk(inputUrl.value || "");
  if (!raw) {
    setStatus("Paste a URL first.");
    toast("No URL pasted", "Provide the suspicious link.");
    return;
  }

  // Normalize for parsing:
  // 1) refang common obfuscations
  // 2) add scheme if missing
  const refanged = refangAll(raw);
  const withScheme = ensureScheme(refanged);

  let urlObj;
  try {
    urlObj = new URL(withScheme);
  } catch {
    setStatus("Couldn’t parse that URL. It’s being difficult on purpose.");
    toast("Parse failed", "Try removing extra text around the URL.");
    return;
  }

  const normalized = urlObj.toString();
  const decoded = safeMultiDecode(normalized);

  // Render normalized/decoded (defanged if toggle on)
  const normOut = toggleDefang.checked ? defangAll(normalized) : normalized;
  const decOut = toggleDefang.checked ? defangAll(decoded) : decoded;

  outNormalized.textContent = normOut;
  outDecoded.textContent = decOut;

  bScheme.textContent = urlObj.protocol.replace(":", "") || "—";
  bHost.textContent = toggleDefang.checked ? urlObj.hostname.replaceAll(".", "[.]") : urlObj.hostname;
  bPath.textContent = urlObj.pathname || "/";

  renderParams(urlObj);

  const flags = buildFlags(urlObj, raw, normalized, decoded);
  renderFlags(flags);

  // VT search link (safe lookup; does not open URL)
  const vtQ = encodeURIComponent(normalized);
  vtSearch.href = `https://www.virustotal.com/gui/search/${vtQ}`;

  lastJson = buildJson(urlObj, normalized, decoded, flags);

  const realFlags = flags[0]?.startsWith("No obvious red flags") ? 0 : flags.length;
  setStatus(realFlags
    ? `Analyzed. ${realFlags} structure flag(s). (It’s giving “investigate further” 👀)`
    : "Analyzed. No obvious structural red flags (still check reputation/logs).");

  toast("Analysis complete ✨", toggleDefang.checked ? "Outputs defanged for safety." : "Danger mode: outputs are raw.");
}

function clearAll() {
  inputUrl.value = "";
  outNormalized.textContent = "—";
  outDecoded.textContent = "—";
  bScheme.textContent = "—";
  bHost.textContent = "—";
  bPath.textContent = "—";
  paramsBody.innerHTML = `<tr><td class="muted" colspan="2">—</td></tr>`;
  flagsList.innerHTML = `<li class="muted">—</li>`;
  flagCount.textContent = "0 flags";
  lastJson = null;
  vtSearch.href = "#";
  setStatus("Cleared. Fresh slate.");
  toast("Cleared", "URL destroyed (peace restored).");
}

function loadSample() {
  inputUrl.value = "hxxps://micros0ft-login.example.com/auth?redirect=https%3A%2F%2Flogin.example.com%2F&session=abc123&utm_source=email%2520blast";
  toast("Sample loaded", "Hit Analyze to see the breakdown.");
  setStatus("Sample loaded. Click Analyze.");
}

async function copyNormalized() {
  const t = outNormalized.textContent || "";
  if (!t || t === "—") return toast("Nothing to copy", "Analyze a URL first.");
  const ok = await copyText(t);
  toast(ok ? "Copied!" : "Copy failed 😭", ok ? "Normalized URL copied." : "Try manual copy.");
}

async function copyDecoded() {
  const t = outDecoded.textContent || "";
  if (!t || t === "—") return toast("Nothing to copy", "Analyze a URL first.");
  const ok = await copyText(t);
  toast(ok ? "Copied!" : "Copy failed 😭", ok ? "Decoded URL copied." : "Try manual copy.");
}

async function copyJson() {
  if (!lastJson) return toast("No JSON yet", "Analyze a URL first.");
  const ok = await copyText(JSON.stringify(lastJson, null, 2));
  toast(ok ? "Copied!" : "Copy failed 😭", ok ? "JSON copied." : "Try manual copy.");
}

function exportJson() {
  if (!lastJson) return toast("No JSON yet", "Analyze a URL first.");
  downloadFile("url-analysis.json", JSON.stringify(lastJson, null, 2), "application/json");
  toast("Exported JSON", "File downloaded.");
}

// Events
el("btnAnalyze").addEventListener("click", analyze);
el("btnClear").addEventListener("click", clearAll);
el("btnSample").addEventListener("click", loadSample);

el("copyNormalized").addEventListener("click", copyNormalized);
el("copyDecoded").addEventListener("click", copyDecoded);
el("copyJson").addEventListener("click", copyJson);
el("exportJson").addEventListener("click", exportJson);

toggleDefang.addEventListener("change", () => {
  toast(toggleDefang.checked ? "Defang ON 😇" : "Defang OFF 😈",
        toggleDefang.checked ? "No accidental clicks today." : "Proceed with caution.");
  // Re-render if already analyzed
  if (lastJson) analyze();
});

// Init
setStatus("Ready. Paste a URL and hit Analyze.");

