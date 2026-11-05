// Frontend logic for the web UI: collect inputs, call the backend, render results.
//
// The backend does all the real work (forging tokens, sending requests, running checks).
// This file only moves data between the form and those endpoints and draws the result.
// We build DOM nodes rather than splicing strings into innerHTML, because findings contain
// live response data and decoded claims from the target; textContent keeps that safe and intact.
// The one exception is icon(), which injects our own static SVG markup.

"use strict";

// --- inline icon set (our own static SVG, 20x20, stroke = currentColor) ---------
const ICONS = {
  check: '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="10" r="6.5"/><circle cx="10" cy="10" r="1.6"/><path d="M10 1.5v2M10 16.5v2M1.5 10h2M16.5 10h2"/></svg>',
};

function icon(name) {
  const span = document.createElement("span");
  span.innerHTML = ICONS[name] || "";   // our own static markup, never user data
  return span.firstElementChild;
}

// --- tiny DOM helpers ------------------------------------------------------
function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else node.setAttribute(k, v);
    }
  }
  for (const child of children || []) {
    if (child != null) node.append(child);
  }
  return node;
}

function clear(node) { node.replaceChildren(); }

async function getJSON(url) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`${resp.status}: ${resp.statusText}`);
  return resp.json();
}

async function postJSON(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try { detail = JSON.stringify((await resp.json()).detail); } catch (_) { /* keep statusText */ }
    throw new Error(`${resp.status}: ${detail}`);
  }
  return resp.json();
}

function skeleton(rows) {
  const box = el("div", { class: "skeleton" });
  for (let i = 0; i < rows; i++) box.append(el("div", { class: "skeleton__row" }));
  return box;
}

function stateBox(title, detail, isError) {
  return el("div", { class: isError ? "state state--error" : "state" }, [
    el("div", { class: "state__title", text: title }),
    detail ? el("p", { text: detail }) : null,
  ]);
}

// --- shared page state -----------------------------------------------------
const state = {
  rawRequest: "",
  token: null,      // the confirmed session token
  maxStep: 1,       // the furthest step reached, so the stepper can jump back to any of them
};

const panels = {
  request: document.getElementById("panel-request"),
  token: document.getElementById("panel-token"),
  checks: document.getElementById("panel-checks"),
  report: document.getElementById("panel-report"),
};
const STEP_KEY = { 1: "request", 2: "token", 3: "checks", 4: "report" };
const mainEl = document.querySelector("main");
const tokenRegion = document.getElementById("token-region");
const checksRegion = document.getElementById("checks-region");
const manualFallback = document.getElementById("manual-fallback");

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// Show exactly one step's panel and hide the others, so each step owns the viewport and the page
// never grows into a long scroll. The furthest step reached stays reachable from the stepper.
function showStep(n) {
  state.maxStep = Math.max(state.maxStep, n);
  for (const [key, panel] of Object.entries(panels)) {
    const active = key === STEP_KEY[n];
    panel.hidden = !active;
    panel.classList.remove("is-in");
    if (active) {
      void panel.offsetWidth;        // reflow so the entrance animation retriggers on re-show
      panel.classList.add("is-in");
    }
  }
  setStep(n);
  if (mainEl) mainEl.scrollTop = 0;  // start each step at the top of the scroll area
}

function setStep(n) {
  for (const item of document.querySelectorAll(".stepper__item")) {
    const s = Number(item.dataset.step);
    item.classList.toggle("is-active", s === n);
    item.classList.toggle("is-done", s < n);
    item.classList.toggle("is-reachable", s <= state.maxStep);
    item.setAttribute("aria-disabled", s <= state.maxStep ? "false" : "true");
  }
}

// --- step 1: detect --------------------------------------------------------
async function onDetect() {
  state.rawRequest = document.getElementById("raw-request").value;
  showStep(2);

  if (!state.rawRequest.trim()) {
    clear(tokenRegion);
    tokenRegion.append(stateBox("Nothing To Scan", "Paste a request above first.", true));
    manualFallback.hidden = true;
    return;
  }

  const btn = document.getElementById("btn-detect");
  busy(btn, true);
  clear(tokenRegion);
  tokenRegion.append(skeleton(2));
  manualFallback.hidden = true;

  try {
    const data = await postJSON("/detect", { raw_request: state.rawRequest });
    renderCandidates(data.candidates);
    manualFallback.hidden = false;   // always offer manual paste as a fallback here
  } catch (err) {
    clear(tokenRegion);
    tokenRegion.append(stateBox("Could Not Read The Request", String(err.message), true));
    manualFallback.hidden = false;
  } finally {
    busy(btn, false);
  }
}

function renderCandidates(candidates) {
  clear(tokenRegion);
  if (!candidates.length) {
    tokenRegion.append(stateBox(
      "No JWTs Detected",
      "Nothing in the request looked like a JWT. Paste the token manually below.",
      false,
    ));
    return;
  }
  const list = el("div", { class: "candidates" });
  candidates.forEach((cand, i) => list.append(candidateCard(cand, i)));
  tokenRegion.append(list);
}

function candidateCard(cand, index) {
  const id = `cand-${index}`;
  const radio = el("input", { type: "radio", name: "token-choice", id, class: "candidate__radio" });
  radio.addEventListener("change", () => selectToken(cand.token, card));

  const alg = cand.header ? (cand.header.alg || "?") : "unreadable";
  const sub = cand.payload ? (cand.payload.sub || cand.payload.user || cand.payload.name || "") : "";

  const top = el("div", { class: "candidate__top" }, [
    radio,
    el("span", { class: "candidate__alg", text: `alg: ${alg}` }),
    sub ? el("span", { class: "candidate__meta", text: `sub: ${sub}` }) : null,
  ]);

  const card = el("label", { class: "candidate", for: id }, [top, coloredToken(cand.token)]);
  card.style.animationDelay = `${index * 60}ms`;

  if (cand.error) {
    card.append(el("p", { class: "candidate__error", text: `Could not decode: ${cand.error}` }));
  } else {
    card.append(decodedBoxes(cand.header, cand.payload));
  }
  return card;
}

// header.payload.signature with each part tinted, like jwt.io
function coloredToken(token) {
  const parts = token.split(".");
  const classes = ["p-header", "p-payload", "p-signature"];
  const raw = el("div", { class: "jwt-raw" });
  parts.forEach((part, i) => {
    if (i > 0) raw.append(el("span", { class: "p-dot", text: "." }));
    raw.append(el("span", { class: classes[i] || "p-signature", text: part }));
  });
  return raw;
}

function decodedBoxes(header, payload) {
  return el("div", { class: "decoded" }, [
    el("div", { class: "decoded__box decoded__box--header" }, [
      el("h4", { text: "Header" }),
      el("pre", { text: JSON.stringify(header, null, 2) }),
    ]),
    el("div", { class: "decoded__box decoded__box--payload" }, [
      el("h4", { text: "Payload" }),
      el("pre", { text: JSON.stringify(payload, null, 2) }),
    ]),
  ]);
}

function selectToken(token, card) {
  state.token = token;
  document.querySelectorAll(".candidate.is-selected").forEach((c) => c.classList.remove("is-selected"));
  if (card) card.classList.add("is-selected");
  showStep(3);
  updateRunState();
}

// --- manual-paste fallback (step 2) ---------------------------------------
function onManual() {
  const token = document.getElementById("manual-token").value.trim();
  if (!token) return;
  state.rawRequest = document.getElementById("raw-request").value;   // still need the request to rebuild
  for (const r of document.querySelectorAll("input[name=token-choice]")) r.checked = false;
  clear(tokenRegion);
  const card = el("label", { class: "candidate is-selected" }, [
    el("div", { class: "candidate__top" }, [el("span", { class: "candidate__alg", text: "manually entered token" })]),
    coloredToken(token),
  ]);
  tokenRegion.append(card);
  selectToken(token, card);
}

// --- step 3: checks --------------------------------------------------------
async function loadChecks() {
  try {
    const data = await getJSON("/checks");
    clear(checksRegion);
    for (const check of data.checks) checksRegion.append(checkRow(check));
    updateMaster();
    updateRunState();     // set each chip, hide every (collapsed) panel, render the run-block banner
  } catch (err) {
    clear(checksRegion);
    checksRegion.append(stateBox("Could Not Load Checks", String(err.message), true));
  }
}

function checkRow(check) {
  const input = el("input", { type: "checkbox", class: "check__box", id: `check-${check.name}`, value: check.name });
  input.addEventListener("change", onCheckChange);
  // One compact line per check: checkbox + title + (optional) requirement pill, with the full
  // description as a hover tooltip so the list stays short enough to fit without scrolling.
  const label = el("label", { class: "check", for: `check-${check.name}`, title: check.description || "" }, [
    input,
    icon("check"),
    el("div", { class: "check__text" }, [
      el("span", { class: "check__title", text: check.title }),
      check.requires_wordlist ? el("span", { class: "check__badge", text: "Wordlist required" }) : null,
      check.requires_hosted_jwks ? el("span", { class: "check__badge", text: check.hosted_jwks_badge || "Hosting required" }) : null,
    ]),
  ]);

  // The config a check needs lives in a panel that stays COLLAPSED under the compact row until the
  // tester opens it with the row's chip, so ticking every check never balloons the list. The panel
  // is kept OUTSIDE the <label> so typing in it can't toggle the checkbox.
  let panel = null;
  if (check.requires_wordlist) panel = wordlistControl(check);
  else if (check.requires_hosted_jwks) panel = jkuControl(check);
  else if (check.kid_file_option) panel = kidFileControl(check);
  else if (check.pubkey_option) panel = pubkeyControl(check);

  const head = el("div", { class: "check-head" }, [label]);
  const group = el("div", { class: "check-group", "data-check": check.name, "data-title": check.title }, [head]);
  if (panel) {
    const chip = el("button", { type: "button", class: "check__toggle", hidden: "hidden",
                                "aria-expanded": "false", "aria-controls": `panel-${check.name}` });
    chip.addEventListener("click", () => togglePanel(check.name));
    head.append(chip);
    panel.id = `panel-${check.name}`;
    group.append(panel);
  }
  return group;
}

function groupFor(name) {
  return checksRegion.querySelector(`.check-group[data-check="${name}"]`);
}

function isOpen(name) {
  const g = groupFor(name);
  return !!(g && g.classList.contains("is-open"));
}

// Expand/collapse one check's config panel (the row chip toggles it). updateRunState re-applies
// every panel's visibility and keeps the chips and the run-block banner in sync.
function togglePanel(name) {
  const g = groupFor(name);
  if (!g) return;
  g.classList.toggle("is-open");
  updateRunState();
}

// Open a check's panel, ticking the check first if needed, and bring it into view with its first
// field focused. The run-block banner's "Set it up" button calls this, so a blocked check is one
// click from being fixable.
function openPanel(name) {
  const box = document.getElementById(`check-${name}`);
  if (box && !box.checked) box.checked = true;
  const g = groupFor(name);
  if (g) g.classList.add("is-open");
  updateMaster();
  updateRunState();
  if (g) {
    g.scrollIntoView({ behavior: "smooth", block: "center" });
    const field = g.querySelector('input[type="url"], input[type="text"], textarea:not([readonly])');
    if (field) field.focus({ preventScroll: true });
  }
}

// Reflect one check's control state on its row chip and record any blocking reason on the group,
// so collectBlockers (and so the banner + Run button) can read it. `kind` is "block" (red, must be
// fixed), "ready" (green, configured) or "options" (neutral, optional).
function setControlState(name, active, kind, chipText, blockReason) {
  const g = groupFor(name);
  if (!g) return;
  const chip = g.querySelector(".check__toggle");
  if (chip) {
    chip.hidden = !active;                 // no point offering setup for an unselected check
    chip.textContent = chipText;           // the caret is a ::after pseudo-element, kept intact
    chip.classList.toggle("is-blocking", kind === "block");
    chip.classList.toggle("is-ready", kind === "ready");
    chip.classList.toggle("is-options", kind === "options");
    chip.setAttribute("aria-expanded", g.classList.contains("is-open") ? "true" : "false");
  }
  if (active && kind === "block") g.dataset.blockReason = blockReason;
  else delete g.dataset.blockReason;
}

// The wordlist picker for a check that requires one: a built-in-list toggle plus an upload/paste
// box. Required means a source must be chosen, if the built-in list is off and nothing is
// pasted, the warning shows and Run is blocked (see refreshWordlists).
function wordlistControl(check) {
  const count = check.builtin_wordlist_count || 0;

  const builtin = el("input", { type: "checkbox", class: "wordlist__builtin", checked: "checked" });
  builtin.addEventListener("change", updateRunState);

  const text = el("textarea", { class: "wordlist__text", spellcheck: "false",
                                placeholder: "…or paste secrets here, one per line" });
  text.addEventListener("input", updateRunState);

  const file = el("input", { type: "file", class: "wordlist__file", accept: ".txt,text/plain", hidden: "hidden" });
  const fileNote = el("span", { class: "wordlist__file-note hint" });
  const upload = el("button", { type: "button", class: "btn btn--ghost btn--sm wordlist__upload", text: "Upload .txt" });
  upload.addEventListener("click", () => file.click());
  file.addEventListener("change", async () => {
    const chosen = file.files && file.files[0];
    if (!chosen) return;
    try {
      text.value = await chosen.text();        // load the file into the paste box, so it's editable
      fileNote.textContent = `Loaded ${chosen.name}`;
    } catch (_) {
      fileNote.textContent = "Could not read that file.";
    }
    file.value = "";                            // let the same file be re-picked later
    updateRunState();
  });

  return el("div", { class: "wordlist", "data-check": check.name }, [
    el("label", { class: "wordlist__builtin-row" }, [
      builtin, el("span", { text: `Use built-in list (${count} common secrets)` }),
    ]),
    el("div", { class: "wordlist__row" }, [upload, fileNote, file]),
    text,
    el("p", { class: "wordlist__warn", hidden: "hidden",
              text: "No wordlist selected, turn on the built-in list, add your own, or uncheck this check." }),
  ]);
}

// Sync every wordlist control to its check and return whether any one blocks the run. A control
// whose check is unchecked is dimmed and ignored; an active one with no source shows its warning.
function refreshWordlists() {
  let blocking = false;
  for (const wl of checksRegion.querySelectorAll(".wordlist")) {
    const name = wl.dataset.check;
    const box = document.getElementById(`check-${name}`);
    const active = !!(box && box.checked);
    const open = isOpen(name);
    wl.hidden = !(active && open);   // show the picker only when its check is selected AND expanded

    const hasBuiltin = wl.querySelector(".wordlist__builtin").checked;
    const hasPasted = wl.querySelector(".wordlist__text").value.trim() !== "";
    const noSource = active && !hasBuiltin && !hasPasted;
    wl.querySelector(".wordlist__warn").hidden = !(noSource && open);
    setControlState(name, active, noSource ? "block" : "options",
                    noSource ? "Needs setup" : "Options",
                    "needs a wordlist: turn on the built-in list or paste one");
    if (noSource) blocking = true;
  }
  return blocking;
}

// The hosting control for a check that needs the tester to host a key set (jku_injection). The
// tool generates the keypair (backend /prepare) and shows the JWK Set to host; the tester hosts
// it and pastes the URL. "Required" means both must be in place, until then the warning shows
// and Run is blocked (see refreshHosted). Kept OUTSIDE the check's <label> like the wordlist one.
function jkuControl(check) {
  const control = el("div", { class: "jku", "data-check": check.name });

  const hint = el("p", { class: "jku__hint hint", text: check.hosted_jwks_hint || "" });

  const gen = el("button", { type: "button", class: "btn btn--ghost btn--sm jku__gen", text: "Generate key set" });
  gen.addEventListener("click", () => generateHostedMaterial(control, check.name));
  const status = el("span", { class: "jku__status hint" });

  const jwks = el("textarea", { class: "jku__jwks", readonly: "readonly", spellcheck: "false",
                                rows: "8", "aria-label": "JWK Set to host" });
  const copy = el("button", { type: "button", class: "btn btn--ghost btn--sm jku__copy", text: "Copy" });
  copy.addEventListener("click", () => copyText(jwks.value, copy));
  const jwksWrap = el("div", { class: "jku__jwks-wrap", hidden: "hidden" }, [
    el("div", { class: "jku__jwks-head" }, [
      el("span", { class: "hint", text: "Host this JWK Set where the target can fetch it:" }), copy,
    ]),
    jwks,
  ]);

  const url = el("input", { type: "url", class: "jku__url", spellcheck: "false",
                            placeholder: "https://your-host/jwks.json, the jku URL" });
  url.addEventListener("input", updateRunState);

  const warn = el("p", { class: "jku__warn", hidden: "hidden",
                         text: "Generate the key set, host it, and paste its URL, or uncheck this check." });

  control.append(hint, el("div", { class: "jku__row" }, [gen, status]), jwksWrap, url, warn);
  return control;
}

// Ask the backend to generate this check's keypair + JWK Set, show the set to host, and keep the
// private key + kid on the control so onRun can send them back with the scan (so the forged token
// is signed by the key that matches the hosted public half). The private key never leaves this box.
async function generateHostedMaterial(control, name) {
  const gen = control.querySelector(".jku__gen");
  const status = control.querySelector(".jku__status");
  busy(gen, true);
  status.textContent = "Generating…";
  try {
    const m = await postJSON(`/prepare/${name}`, {});
    control._material = { kid: m.kid, pem: m.private_key_pem };
    control.querySelector(".jku__jwks").value = m.jwks_text;
    control.querySelector(".jku__jwks-wrap").hidden = false;
    gen.textContent = "Regenerate key set";
    status.textContent = "Key set generated, host it, then paste its URL below.";
  } catch (err) {
    status.textContent = "Could not generate: " + err.message;
  } finally {
    busy(gen, false);
    updateRunState();
  }
}

// Copy text to the clipboard, flashing the button label. Clipboard may be unavailable (insecure
// context); fail quietly, the text is still selectable in the box.
async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const prev = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => { btn.textContent = prev; }, 1200);
  } catch (_) { /* clipboard blocked; the textarea is still selectable */ }
}

// Sync every hosting control to its check and return whether any one blocks the run. When a
// check is first selected we auto-generate its key set (so the box fills with text to host the
// moment it opens); an active control still missing its key set or URL shows its warning.
function refreshHosted() {
  let blocking = false;
  for (const ctl of checksRegion.querySelectorAll(".jku")) {
    const name = ctl.dataset.check;
    const box = document.getElementById(`check-${name}`);
    const active = !!(box && box.checked);
    const open = isOpen(name);
    ctl.hidden = !(active && open);   // show the hosting control only when selected AND expanded

    // Generate the key set the first time its panel is actually opened (not merely selected), so we
    // never mint a keypair for a check the tester ticks under "Select all" but never configures.
    if (active && open && !ctl._material && !ctl._generating) {
      ctl._generating = true;         // guard against re-entry while the request is in flight
      generateHostedMaterial(ctl, name).finally(() => { ctl._generating = false; });
    }
    const ready = !!ctl._material && ctl.querySelector(".jku__url").value.trim() !== "";
    ctl.querySelector(".jku__warn").hidden = ready || !open;
    setControlState(name, active, ready ? "ready" : "block",
                    ready ? "Ready" : "Needs setup",
                    "needs its key set hosted and the hosted URL pasted");
    if (active && !ready) blocking = true;
  }
  return blocking;
}

// The optional known-file control for kid_path_traversal: a server-side file path and, optionally,
// that file's known contents. Both are optional, so this control NEVER blocks the run; left blank,
// the check still tests an empty file and an auto-discovered asset. Kept OUTSIDE the check's <label>
// like the other controls so typing doesn't toggle the checkbox.
function kidFileControl(check) {
  const path = el("input", { type: "text", class: "kidfile__path", spellcheck: "false",
                             placeholder: "Server-side file path, e.g. /dev/null (optional)" });
  const key = el("textarea", { class: "kidfile__key", spellcheck: "false", rows: "2",
                               placeholder: "Known contents of that file (optional); blank = fetch it from the target" });
  return el("div", { class: "kidfile", "data-check": check.name }, [
    el("p", { class: "kidfile__hint hint", text: check.kid_file_hint || "" }),
    path,
    key,
  ]);
}

// Show each kid-file control only while its check is ticked (like the wordlist/hosting controls).
// It is optional, so this never blocks the run and returns nothing.
function refreshKidFile() {
  for (const ctl of checksRegion.querySelectorAll(".kidfile")) {
    const name = ctl.dataset.check;
    const box = document.getElementById(`check-${name}`);
    const active = !!(box && box.checked);
    ctl.hidden = !(active && isOpen(name));
    setControlState(name, active, "options", "Options", null);
  }
}

// The optional public-key control for algorithm_confusion: a pasted PEM/certificate or a JWKS URL
// to fetch. Both optional (auto-discovery always runs), so this NEVER blocks the run. Kept OUTSIDE
// the <label> so typing doesn't toggle the check.
function pubkeyControl(check) {
  const pem = el("textarea", { class: "pubkey__pem", spellcheck: "false", rows: "3",
                               placeholder: "Public key PEM or X.509 certificate (optional)" });
  const url = el("input", { type: "url", class: "pubkey__url", spellcheck: "false",
                            placeholder: "JWKS URL to fetch the key from (optional)" });
  return el("div", { class: "pubkey", "data-check": check.name }, [
    el("p", { class: "pubkey__hint hint", text: check.pubkey_hint || "" }),
    pem,
    url,
  ]);
}

// Show each public-key control only while its check is ticked. Optional, so it never blocks the run.
function refreshPubkey() {
  for (const ctl of checksRegion.querySelectorAll(".pubkey")) {
    const name = ctl.dataset.check;
    const box = document.getElementById(`check-${name}`);
    const active = !!(box && box.checked);
    ctl.hidden = !(active && isOpen(name));
    setControlState(name, active, "options", "Options", null);
  }
}

function checkBoxes() {
  // Only the attack-selection boxes, NOT the wordlist controls' own checkboxes, which also
  // live in this region and must never be counted as a selected check (their value is "on").
  return [...checksRegion.querySelectorAll("input.check__box")];
}

function selectedChecks() {
  return checkBoxes().filter((b) => b.checked).map((b) => b.value);
}

function updateRunState() {
  // Each refresh re-applies its panel's visibility and stamps a block reason on the group when a
  // selected check still needs setup; we then gather those into the run-block banner.
  refreshWordlists();
  refreshHosted();
  refreshKidFile();   // optional control: never blocks the run
  refreshPubkey();    // likewise for the algorithm-confusion public-key control
  const blockers = collectBlockers();
  renderRunBlock(blockers);
  document.getElementById("btn-run").disabled =
    !(state.token && selectedChecks().length) || blockers.length > 0;
}

// Selected checks that still need setup, read from the block reason each refresh stamped on the
// group. These both block Run and populate the banner above it.
function collectBlockers() {
  const out = [];
  for (const g of checksRegion.querySelectorAll(".check-group[data-block-reason]")) {
    const box = document.getElementById(`check-${g.dataset.check}`);
    if (!box || !box.checked) continue;
    out.push({ name: g.dataset.check, title: g.dataset.title || g.dataset.check, reason: g.dataset.blockReason });
  }
  return out;
}

// The loud, always-visible reason Run is disabled: a banner right above the button naming each
// check that needs setup, each with a "Set it up" button that opens its panel. Replaces the old
// fine-print warning buried inside a collapsed panel far down the list.
function renderRunBlock(blockers) {
  const box = document.getElementById("run-block");
  if (!box) return;   // older cached page without the banner element: skip it, don't break the list
  clear(box);
  if (!blockers.length) { box.hidden = true; return; }
  box.hidden = false;
  const items = blockers.map((b) => {
    const fix = el("button", { type: "button", class: "run-block__fix", text: "Set it up" });
    fix.addEventListener("click", () => openPanel(b.name));
    return el("li", { class: "run-block__item" }, [
      el("span", { class: "run-block__text", text: `${b.title} ${b.reason}.` }),
      fix,
    ]);
  });
  box.append(
    el("p", { class: "run-block__title",
              text: blockers.length === 1 ? "One check still needs setup before you can run:"
                                          : "Some checks still need setup before you can run:" }),
    el("ul", { class: "run-block__list" }, items),
  );
}

function onCheckChange() {
  updateMaster();
  updateRunState();
}

// Keep the "Select all" master box in sync: checked when all are, cleared when none, a dash between.
function updateMaster() {
  const boxes = checkBoxes();
  const master = document.getElementById("check-all");
  const on = boxes.filter((b) => b.checked).length;
  master.checked = boxes.length > 0 && on === boxes.length;
  master.indeterminate = on > 0 && on < boxes.length;
}

function onMasterToggle() {
  const master = document.getElementById("check-all");
  for (const b of checkBoxes()) b.checked = master.checked;
  master.indeterminate = false;
  updateRunState();
}

// The report opens in a new tab the instant the user clicks Run, but the scan takes a moment,
// so we fill that tab with a branded loading screen right away instead of leaving it blank
// (a blank tab reads as "broken"). Once the scan finishes we point the tab at the real report.
const REPORT_LOADING_DOC = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Generating report…</title>
<style>
  :root { color-scheme: dark; }
  html, body { height: 100%; margin: 0; }
  body { display: grid; place-items: center;
    background: radial-gradient(1000px 620px at 50% -12%, #18304a, transparent 60%), linear-gradient(180deg, #0e1824, #0b111b);
    color: #e9eef5; font-family: "Segoe UI Variable Text", system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; }
  .box { display: grid; justify-items: center; gap: 1.2rem; text-align: center; padding: 2rem; }
  .ring { width: 3.5rem; height: 3.5rem; border-radius: 50%; border: 4px solid rgba(255,255,255,0.14); border-top-color: #17b9ab; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  h1 { font-size: 1.15rem; font-weight: 600; margin: 0; }
  p { margin: 0; color: #9fb4ca; font-size: 0.92rem; max-width: 32ch; line-height: 1.5; }
  @media (prefers-reduced-motion: reduce) { .ring { animation-duration: 2.4s; } }
</style></head><body><div class="box">
  <div class="ring"></div>
  <h1>Running checks…</h1>
  <p>Forging tokens and sending your request. Your detailed report will appear here in a moment.</p>
</div></body></html>`;

// The error page reuses the loading shell with the spinner and copy removed. The message is
// deliberately NOT spliced into this HTML: writeErrorTab sets it as text afterwards.
function errorShellDoc() {
  return REPORT_LOADING_DOC
    .replace("Running checks…", "Scan failed")
    .replace(/<div class="ring"><\/div>/, "")
    .replace(/Forging tokens[^<]*/, "");
}

function writeTab(tab, html) {
  try { tab.document.open(); tab.document.write(html); tab.document.close(); } catch (_) { /* cross-origin or closed */ }
}

// Write the error page, then set the message with textContent rather than building it into the
// HTML string. An error can quote a server response, so treating it as markup would let that
// text inject nodes into this tab; textContent also avoids `$&`-style replacement patterns
// mangling the page.
function writeErrorTab(tab, message) {
  writeTab(tab, errorShellDoc());
  try {
    const line = tab.document.querySelector(".box p");
    if (line) line.textContent = String(message) + ", close this tab and try again.";
  } catch (_) { /* cross-origin or closed */ }
}

// --- step 4: run, then open the detailed report ----------------------------
async function onRun() {
  const scheme = document.querySelector("input[name=scheme]:checked").value;
  const checks = selectedChecks();
  const btn = document.getElementById("btn-run");
  busy(btn, true);

  showStep(4);
  showRunning();

  // Reserve the report tab now, inside the click gesture, so the browser doesn't treat the
  // post-await window.open as an unsolicited popup and block it, and fill it immediately with
  // a loading screen so it never shows as a blank "broken" tab.
  const reportTab = window.open("about:blank", "_blank");
  if (reportTab) writeTab(reportTab, REPORT_LOADING_DOC);

  const body = { raw_request: state.rawRequest, token: state.token, scheme, checks, check_options: {} };
  // Attach the wordlist settings for any selected check that has a control (weak_secret).
  for (const wl of checksRegion.querySelectorAll(".wordlist")) {
    if (!checks.includes(wl.dataset.check)) continue;
    body.use_builtin_wordlist = wl.querySelector(".wordlist__builtin").checked;
    body.wordlist = wl.querySelector(".wordlist__text").value;
  }
  // Attach the hosted-key-set settings for any selected hosting check (jku_injection): the URL
  // the tester hosted at, plus the generated key that matches it.
  for (const ctl of checksRegion.querySelectorAll(".jku")) {
    if (!checks.includes(ctl.dataset.check) || !ctl._material) continue;
    body.check_options[ctl.dataset.check] = {
      jku_url: ctl.querySelector(".jku__url").value.trim(),
      private_key_pem: ctl._material.pem,
      kid: ctl._material.kid,
    };
  }
  // Attach the optional known-file settings for the kid check: a server-side path and/or the
  // file's known contents. Both optional, so we only send the keys the tester actually filled in.
  for (const ctl of checksRegion.querySelectorAll(".kidfile")) {
    if (!checks.includes(ctl.dataset.check)) continue;
    const filePath = ctl.querySelector(".kidfile__path").value.trim();
    const fileKey = ctl.querySelector(".kidfile__key").value;
    const options = {};
    if (filePath) options.kid_file_path = filePath;
    if (fileKey) options.kid_file_key = fileKey;
    if (Object.keys(options).length) body.check_options[ctl.dataset.check] = options;
  }
  // Attach the optional public-key settings for algorithm_confusion: a pasted PEM/cert and/or a
  // JWKS URL to fetch. Both optional, so only non-empty fields are sent.
  for (const ctl of checksRegion.querySelectorAll(".pubkey")) {
    if (!checks.includes(ctl.dataset.check)) continue;
    const pem = ctl.querySelector(".pubkey__pem").value.trim();
    const jwksUrl = ctl.querySelector(".pubkey__url").value.trim();
    const options = {};
    if (pem) options.public_key_pem = pem;
    if (jwksUrl) options.jwks_url = jwksUrl;
    if (Object.keys(options).length) body.check_options[ctl.dataset.check] = options;
  }

  try {
    await postJSON("/scan", body);
    if (reportTab && !reportTab.closed) reportTab.location.replace("/report");
    else window.open("/report", "_blank");   // reserve failed (popup blocked); try once more
    showReportReady();
  } catch (err) {
    if (reportTab && !reportTab.closed) writeErrorTab(reportTab, err.message);
    showRunError(err.message);
  } finally {
    busy(btn, false);
  }
}

function showRunning() {
  document.getElementById("report-spinner").hidden = false;
  document.getElementById("report-actions").hidden = true;
  setReportStatus("Running checks…",
                  "Forging tokens and sending your request. The report will open in a new tab.", false);
}

function showReportReady() {
  document.getElementById("report-spinner").hidden = true;
  document.getElementById("report-actions").hidden = false;   // manual fallback button
  setReportStatus("Report ready", "Your detailed report opened in a new tab.", false);
}

function showRunError(message) {
  document.getElementById("report-spinner").hidden = true;
  document.getElementById("report-actions").hidden = true;
  setReportStatus("Scan Failed", String(message), true);
}

function setReportStatus(title, hint, isError) {
  const titleEl = document.getElementById("report-status-title");
  const hintEl = document.getElementById("report-status-hint");
  titleEl.textContent = title;
  titleEl.classList.toggle("is-error", !!isError);
  hintEl.textContent = hint;
}

function onOpenReport() {
  window.open("/report", "_blank", "noopener");
}

function busy(btn, on) {
  btn.setAttribute("aria-busy", on ? "true" : "false");
  btn.disabled = on;
}

// --- wire up ---------------------------------------------------------------
document.getElementById("btn-detect").addEventListener("click", onDetect);
document.getElementById("btn-manual").addEventListener("click", onManual);
document.getElementById("check-all").addEventListener("change", onMasterToggle);
document.getElementById("btn-run").addEventListener("click", onRun);
document.getElementById("btn-open-report").addEventListener("click", onOpenReport);

// The stepper doubles as back-navigation: any step already reached can be reopened (state is kept,
// so going back to edit the request and forward again preserves the chosen token and checks).
for (const item of document.querySelectorAll(".stepper__item")) {
  const go = () => { const s = Number(item.dataset.step); if (s <= state.maxStep) showStep(s); };
  item.setAttribute("role", "button");
  item.setAttribute("tabindex", "0");
  item.addEventListener("click", go);
  item.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); }
  });
}

document.getElementById("year").textContent = new Date().getFullYear();
showStep(1);
loadChecks();
