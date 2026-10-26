"use strict";
// The launch link printed by the server carries the token in its fragment. Keep it in
// memory only and remove it from the address bar and history entry.
const bootstrap = (() => {
  const match = /^#token=([A-Za-z0-9_-]{20,})$/.exec(location.hash);
  if (match) history.replaceState(null, "", location.pathname);
  return match ? match[1] : null;
})();
// Pasting the terminal link into an open tab changes only the fragment; reload to read it.
window.addEventListener("hashchange", () => {if (/^#token=/.test(location.hash)) location.reload();});
const root = document.querySelector("#private-app");
const errorBox = document.querySelector("#private-error");
const message = document.querySelector("#private-message");
const idleBox = document.querySelector("#private-idle");
// Before a session the page shows the full introduction. Once started, a slim header holds the five
// tabs, and the guides move under Help; they move back when the session locks or ends.
const header = document.querySelector("#app-header"), beforeStart = document.querySelector("#before-start");
const guides = ["#drop-guide", "#user-guide", "#requirements-panel"].map(id => document.querySelector(id)).filter(Boolean);
const headerDefault = header ? Array.from(header.childNodes || header.children || []) : [];
// The control whose result the next message describes; banners sit beside it (A4).
let actionLabel = null;
function setRoot(...nodes) {
  // Banners may sit inside the view; return them home first so replacing it never detaches them.
  if (root.before) root.before(errorBox, message);
  root.replaceChildren(...nodes);
}
let endNote = null;  // The last end or delete result, shown on the entry screen until a new start.
// How approved emails go out: "self" (your mail app) or "velum". Held in this page's memory only.
let sendMethod = null, leavingForMail = 0;
let session = null, record = null, status = null, busy = false, generation = 0, lastTouch = 0;
let workState = null, selectedCase = null, keyNotice = "", pendingAuthorize = null;
let workspaceView = "home", identityDirty = false, submissionState = null;
// The Approve-and-next review (which emails, and what you did with each) and the open send confirmation.
let stepper = null, pendingSend = null;

function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}
function button(label, handler, cls = "secondary") {
  const node = el("button", label, cls); node.type = "button";
  node.addEventListener("click", event => { if (label) actionLabel = label; return handler(event); }); return node;
}
function wipe() {
  generation += 1; session = record = workState = selectedCase = null;
  keyNotice = ""; pendingAuthorize = null; identityDirty = false; submissionState = null; workspaceView = "home";
  stepper = pendingSend = actionLabel = null;
  setRoot(); message.textContent = "";
  restoreHeader(); placeBanners();
}
function restoreHeader() {
  if (header) { header.replaceChildren(...headerDefault); header.className = ""; }
  if (beforeStart) { beforeStart.hidden = false; guides.forEach(g => beforeStart.append(g)); }
}
const TABS = [["home", "Home", "do"], ["queue", "Your requests", "review"], ["information", "My information"], ["submissions", "History"], ["coverage", "Coverage"]];
const TAB_OF = {approve: "queue", "send-choice": "queue"};
function shownView() {
  // Before information is saved (or while an upgrade is due) the tabs all show that screen instead.
  const view = TAB_OF[workspaceView] || workspaceView;
  if (["help", "settings", "end", "convert", "send-choice"].includes(workspaceView) || !record) return view;
  if (record.migration_required) return null;
  return record.profile ? view : "information";
}
function renderHeader() {
  if (beforeStart) beforeStart.hidden = true;
  if (!header) return;
  const counts = (workState && workState.attention || {}).counts || {}, here = shownView();
  const brand = el("span", "Velum", "wordmark"), nav = el("nav", undefined, "app-nav"), tools = el("div", undefined, "app-tools");
  brand.append(el("span", "SYNTHETIC BUILD", "tag"));
  nav.setAttribute("aria-label", "Sections");
  for (const [view, title, count] of TABS) {
    const b = button(title + (count && counts[count] ? " (" + counts[count] + ")" : ""), () => changeView(view), "tab");
    if (here === view) b.setAttribute("aria-current", "page");
    nav.append(b);
  }
  const help = button("Help", () => changeView("help"), "link"), settings = button("Privacy & settings", () => changeView("settings"), "link");
  if (here === "help") help.setAttribute("aria-current", "page");
  if (here === "settings") settings.setAttribute("aria-current", "page");
  const inSession = sessionOnly();
  tools.append(el("span", inSession ? "Session only: nothing is kept" : "Encrypted record, unlocked", "mode-label"), help, settings,
    inSession ? button("End session", () => changeView("end")) : button("Lock", () => { wipe(); renderLocked(); run(async () => { await api("/api/lock", {}); }); }));
  header.replaceChildren(brand, nav, tools); header.className = "app-header";
}
function placeBanners() {
  // Results and errors sit beside the control that caused them; otherwise at the top of the view.
  const target = actionLabel && root.querySelectorAll ? Array.from(root.querySelectorAll("button")).find(b => b.textContent === actionLabel) : null;
  const anchor = target && (target.closest?.(".actions") || target);  // Just below the button or its row.
  if (anchor && anchor.after) anchor.after(errorBox, message);
  else if (root.before) root.before(errorBox, message);
}
async function api(path, body) {
  let response;
  try {
    response = await fetch(path, {method: body === undefined ? "GET" : "POST",
      headers: {"X-App-Token": bootstrap, "X-Private-Session": session || "", "Content-Type": "application/json"},
      body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store"});
  } catch (_) {
    throw new Error("Velum's local server is not responding. Your last action may or may not have been recorded. Restart Velum and open its new link to see what was saved; nothing is retried automatically.");
  }
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.error || "Local operation failed");
    error.passphraseSetup = result.passphrase_setup === true;
    throw error;
  }
  return result;
}
async function run(work) {
  if (busy) return;
  busy = true; errorBox.hidden = true;
  const controls = [...root.querySelectorAll("button, input, select, textarea"), ...(header?.querySelectorAll ? header.querySelectorAll("button") : [])];
  const buttons = controls.map(b => [b,b.disabled]);
  buttons.forEach(([b]) => b.disabled = true);
  const current = generation;
  try { await work(current); }
  catch (error) {
    placeBanners();
    errorBox.textContent = error.message; errorBox.hidden = false; message.textContent = "";  // No stale success line.
    errorBox.setAttribute("tabindex", "-1"); errorBox.focus?.(); errorBox.scrollIntoView?.({block: "center"});
  }
  finally {
    busy = false;
    buttons.forEach(([b,disabled]) => {if (b.isConnected) b.disabled = disabled;});
    if (message.textContent && errorBox.hidden) message.scrollIntoView?.({block: "nearest"});
    try { await refresh(); } catch (_) { wipe(); showUnavailable(); }
  }
}
function showUnavailable() {
  setRoot(el("p", "Velum’s local server isn’t responding, so this page cleared everything it showed. Open the terminal link again to reconnect. A session without saving ends with the server; an encrypted record stays locked until you unlock it.", "notice"));
}
async function refresh() {
  const current = generation;
  const next = await api("/api/status");
  if (current !== generation) return;
  const changed = !status || ["locked","initialized","deletion_pending","store","vault_exists"].some(k => next[k] !== status[k]);
  status = next;
  // Another start or unlock replaces this tab's session; clear on that, a lock or an end.
  if (session && (next.locked || !next.session_valid)) { wipe(); renderLocked(); }
  else if (!session && changed) renderLocked();
  renderIdle();
}
// Idle expiry: a session-only workspace is erased, an encrypted record only locks. Warn first.
let idleText = null;
function renderIdle() {
  if (!idleBox) return;
  const left = session && status ? status.remaining_seconds : null;
  if (typeof left !== "number" || left > 60) { idleBox.hidden = true; idleText = null; idleBox.replaceChildren(); return; }
  const clock = Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0");
  const text = status.store === "session" ? "You’ve been away for a while. This session ends in " + clock + ", and everything Velum holds for it is erased."
    : "You’ve been away for a while. Your encrypted record locks in " + clock + ".";
  if (idleText) { idleText.textContent = text; return; }  // Keep the button, and keyboard focus, in place.
  idleText = el("span", text);
  idleBox.replaceChildren(idleText, button("Keep working", keepWorking, "primary")); idleBox.hidden = false;
}
function keepWorking() {
  lastTouch = Date.now();
  api("/api/touch", {}).then(refresh).catch(() => {wipe(); showUnavailable();});
}
async function acceptUnlock(result, current) {
  if (current !== generation) {
    wipe();
    await api("/api/lock", {});
    status = await api("/api/status"); renderLocked();
    return;
  }
  session = result.session; record = result; keyNotice = result.notice || ""; endNote = null;
  status = await api("/api/status");
  const state = await api("/api/cases");
  if (current !== generation) return;
  workState = state; renderWorkspace();
}
const ENDED = {
  ended: "Session ended. Everything Velum held for it was erased.",
  locked: "Session ended. Everything Velum held for it was erased.",
  idle: "Your session ended after a period of inactivity, and everything Velum held for it was erased.",
  error: "Something went wrong, so Velum erased this session to be safe.",
  deleted: "Everything was erased: your records and the encrypted record’s Keychain key are gone from this Mac. An empty database file, holding nothing about you, stays in Velum’s folder."
};
function endedNotice(note) {
  const box = el("section", undefined, "notice"); box.setAttribute("role", "status");
  box.append(el("p", ENDED[note.reason] || ENDED.ended));
  if (note.revoked === true) box.append(el("p", "Google confirmed it revoked Velum’s access."));
  else if (note.revoked === false) {
    const p = el("p", "One step left for you: Velum couldn’t reach Google to revoke its access. Remove Velum on your Google Account’s third-party access page. ");
    p.append(link("Google Account connections ↗", "https://myaccount.google.com/connections")); box.append(p);
  }
  box.append(el("p", "Your Sent folder and the copies brokers received are unchanged.", "muted"));
  return box;
}
function sessionOnly() { return Boolean(status && status.store === "session"); }
function startSession() {
  run(async current => { const result = await api("/api/start", {}); await acceptUnlock(result, current); });
}
function renderLocked() {
  restoreHeader();
  setRoot();
  const note = endNote || (status.ended && status.ended.reason !== "converted" ? status.ended : null);
  if (note) root.append(endedNotice(note));
  const box = el("section", undefined, "detail");
  if (status.deletion_pending) {
    box.append(el("h2", "Finish deleting your encrypted record"), el("p", "Removing its key was interrupted. Its records stay unreadable until deletion finishes."), deletionForm());
  } else if (status.store === "session") {
    box.append(el("h2", "This page can’t reach the open session"),
      el("p", "A session without saving is open, but this page doesn’t hold its key; another tab may. Starting again here erases it."),
      button("Start a new session", startSession, "primary"));
  } else if (status.vault_exists) {
    box.append(el("h2", "Your encrypted record is locked."),
      el("p", "Its key is kept in macOS Keychain, locked by your passphrase. The passphrase is never stored."), unlockForm(),
      el("p", "Or start a session without saving. Nothing from your encrypted record is used, and nothing from the session is kept.", "muted"),
      button("Start without saving", startSession),
      el("p", "Upgrading a vault created before passphrases? Set its first passphrase below.", "muted"),
      button("Set first passphrase for an older vault", () => {setRoot(setupForm());}));
  } else {
    root.append(firstRun()); return;
  }
  root.append(box);
}
function firstRun() {
  const box = el("section", undefined, "detail"), group = el("fieldset", undefined, "mode-options");
  group.append(el("legend", "Before you start: what should Velum keep?"));
  let picked = "session";
  const go = el("button", "Start without saving", "primary"); go.type = "button";
  const hint = el("p", "You can switch to an encrypted record later in this session.", "muted");
  function option(value, title, intro, points, tag) {
    const label = el("label", undefined, "mode-option"), input = el("input"), head = el("span", undefined, "mode-head");
    input.type = "radio"; input.name = "keep"; input.value = value; input.checked = value === picked;
    input.addEventListener("change", () => {
      picked = value;
      go.textContent = value === "session" ? "Start without saving" : "Create an encrypted record";
      hint.textContent = value === "session" ? "You can switch to an encrypted record later in this session." : "Next, choose a passphrase. Velum adds a key to your Keychain.";
    });
    head.append(input, el("strong", title)); if (tag) head.append(el("span", tag, "muted"));
    const list = el("ul"); points.forEach(p => list.append(el("li", p)));
    label.append(head, el("span", intro), list); return label;
  }
  group.append(option("session", "Nothing is kept", "What you enter stays in this page’s memory. It is erased when you end the session, close this page, quit Velum, or stay away too long (Velum warns you first).",
      ["Nothing is written to disk or added to your Keychain.", "Next time, you enter your information again.", "Velum can’t see requests from earlier sessions, so it can’t warn you about duplicates."], "Default"),
    option("vault", "Keep an encrypted record", "Velum tracks every request in an encrypted file stored only on this Mac and tells you when to check for replies. Nothing is uploaded: Velum has no server or account.",
      ["Locked by a key in your Keychain and your passphrase. Lock it any time; it also locks itself when you’re away.", "Warns you before preparing a request a broker may already have.", "Delete everything in one step whenever you like."]));
  go.addEventListener("click", () => {
    if (picked === "session") startSession();
    else { setRoot(createVaultScreen()); }
  });
  const actions = el("div", undefined, "actions"); actions.append(go);
  box.append(group, actions, hint,
    el("p", "Either way, nothing is sent without you: you approve each exact email before it goes.", "notice"), sessionFaq());
  return box;
}
function sessionFaq() {
  const box = el("section", undefined, "faq");
  box.append(el("h3", "What “nothing is kept” means"));
  for (const [q, a] of [
    ["What is erased, and when?", "Your information, the emails you prepared and this session’s history. They live only in memory and are cleared when you end the session, close this page, quit Velum, or the idle timer runs out."],
    ["What still exists somewhere else?", "The emails in your Sent folder, the copies brokers receive, and any Google permission until it is revoked. Velum asks Google to revoke it when the session ends."],
    ["Is that zero risk?", "No. Your Mac can still hold traces in swap files, crash reports or the browser’s memory. Velum writes nothing to disk itself and doesn’t claim more than that."],
    ["What do I give up?", "Reply tracking and duplicate warnings across sessions. You can switch to an encrypted record during a session without entering anything again."]]) {
    const d = el("details", undefined, "history"); d.append(el("summary", q), el("p", a)); box.append(d);
  }
  return box;
}
function passphraseForm(path, submit, onDone) {
  const form = el("form", undefined, "profile-form");
  const first = secret("Passphrase", "new-password"), second = secret("Repeat passphrase", "new-password");
  const ack = consent(" I understand there is no recovery: forgetting the passphrase or losing the Keychain key makes the record unreadable. I will use it only for myself.");
  form.append(first.label, second.label, ack.label);
  submitForm(form, submit, async current => {
    if (!ack.input.checked) throw new Error("Review the recovery limits first: tick the confirmation above.");
    const result = await api(path, {acknowledged:true, passphrase:first.input.value, confirmation:second.input.value});
    await onDone(result, current);
  });
  return form;
}
function createVaultScreen() {
  const box = el("section", undefined, "detail");
  box.append(el("h2", "Create your encrypted record"),
    el("p", "Your record is a file stored only on this Mac; nothing is uploaded, and Velum has no server or account. Personal fields are encrypted before they reach that file. The key is kept in macOS Keychain, locked by your passphrase, which is never stored. No broker password or identity document is collected."),
    el("p", "Choose a passphrase of at least 12 characters that you don’t use anywhere else. There is no backup, recovery export or passphrase reset."),
    passphraseForm("/api/create", "Create and open my encrypted record", acceptUnlock), button("Back", renderLocked));
  return box;
}
function secret(title, autocomplete, minimum = 12) {
  const label = el("label", title), input = el("input");
  input.type = "password"; input.autocomplete = autocomplete; input.required = true; input.minLength = minimum; input.maxLength = 1024;
  label.append(input); return {label, input};
}
function unlockForm() {
  const form = el("form", undefined, "profile-form"), pass = secret("Vault passphrase", "current-password", 1);
  form.append(pass.label);
  submitForm(form, "Unlock vault", async current => {
    try {
      const result = await api("/api/unlock", {passphrase:pass.input.value});
      await acceptUnlock(result, current);
    } catch (error) {
      if (!error.passphraseSetup) throw error;
      setRoot(setupForm());
    }
  });
  return form;
}
function setupForm() {
  // One-time upgrade for a vault created before passphrases existed.
  const box = el("section", undefined, "detail"), form = el("form", undefined, "profile-form");
  const first = secret("New vault passphrase", "new-password"), second = secret("Repeat passphrase", "new-password");
  box.append(el("h2", "Protect this vault with a passphrase"),
    el("p", "This vault was created by an earlier version whose Keychain key unlocked it without any passphrase. Setting one now locks the existing key with it and removes the unprotected copy. Your records are not re-encrypted or changed."),
    el("p", "There is no passphrase reset: forgetting it makes the vault permanently unreadable. Backups made before this step still contain the unprotected key.", "muted"));
  form.append(first.label, second.label);
  submitForm(form, "Set passphrase and unlock", async current => {
    const result = await api("/api/passphrase", {passphrase:first.input.value, confirmation:second.input.value});
    await acceptUnlock(result, current);
  });
  box.append(form, button("Back to unlock", renderLocked)); return box;
}
function deletionForm() {
  const form = el("form", undefined, "profile-form");
  const label = el("label", "Type DELETE to confirm");
  const input = el("input"); input.autocomplete = "off"; input.required = true; label.append(input);
  const submit = el("button", "Delete everything", "danger"); submit.type = "submit";
  form.append(label, submit);
  form.addEventListener("submit", e => { e.preventDefault(); run(async () => {
    const result = await api("/api/delete", {confirmation:input.value, version:record ? record.version : null});
    wipe(); endNote = {reason: "deleted", revoked: result.revoked}; status = result; renderLocked();
  }); });
  return form;
}
function stillElsewhere() {
  return [el("h3", "What stays somewhere else"), el("p", "The emails in your Sent folder and the copies brokers received. Velum can’t erase those.")];
}
function renderDelete() {
  const box = el("section", undefined, "detail"), list = el("ul"), gmail = workState.sender && workState.sender.account;
  list.append(el("li", "Your information, requests and history are erased from this Mac, along with the key in your Keychain."));
  if (gmail) list.append(el("li", "Your Gmail connection is disconnected, and Velum asks Google to revoke it."));
  list.append(el("li", "Duplicate warnings and reply tracking stop, because Velum no longer knows what you sent."));
  box.append(el("h2", "Delete everything"), el("p", "This erases your encrypted record from this Mac. It can’t be undone."), el("h3", "What happens"), list, ...stillElsewhere(), deletionForm());
  return box;
}
function renderEnd() {
  const box = el("section", undefined, "detail"), list = el("ul"), gmail = workState.sender && workState.sender.account;
  list.append(el("li", "Your information, prepared emails and history are erased from memory."));
  if (gmail) list.append(el("li", "Your Gmail connection is disconnected, and Velum asks Google to revoke it."));
  const actions = el("div", undefined, "actions");
  actions.append(button("End session", () => run(async () => {
    const result = await api("/api/end", {});
    wipe(); endNote = {reason: "ended", revoked: result.revoked}; status = result; renderLocked();
  }), "danger"), button("Keep working", () => changeView("information")));
  box.append(el("h2", "End this session"), el("p", "Nothing in this session was meant to last. Ending it erases everything now."), el("h3", "What happens"), list, ...stillElsewhere(), actions,
    el("p", "Want Velum to keep track instead? Switch to an encrypted record before you end.", "muted"), button("Switch to an encrypted record", () => changeView("convert")));
  return box;
}
function renderConvert() {
  const box = el("section", undefined, "detail");
  box.append(el("h2", "Keep this session as an encrypted record"),
    el("p", "Velum moves everything in this session into an encrypted file stored only on this Mac (nothing is uploaded), locked by a key in your Keychain and your passphrase. Nothing needs entering again, and a connected Gmail account stays connected."),
    el("p", "There is no backup, recovery export or passphrase reset.", "muted"),
    passphraseForm("/api/convert", "Switch to an encrypted record", acceptUnlock), button("Back", () => changeView("information")));
  return box;
}
const identityGroups = {
  names: [["full_name","Display name",120],["first_name","First name · optional, never inferred",120],["last_name","Last name · optional, never inferred",120]],
  emails: [["value","Email",254]],
  addresses: [["street_address","Street address",240],["address_line2","Address line 2",240],["city","City",120],["region","State or region",120],["postal_code","Postal code",32],["country","Two-letter country",2],["from_date","From date · optional",10],["to_date","To date · optional",10]],
  phones: [["value","Phone · keep your preferred spelling",64],["country","Two-letter country context",2]]
};
function newIdentifier(group) {
  const row = {id:crypto.randomUUID().replaceAll("-",""),label:"current",preferred:false,retired:false};
  identityGroups[group].forEach(([key]) => row[key] = "");
  if (["emails","phones"].includes(group)) row.reachable = false;
  if (group === "emails") row.use = "unknown";
  return row;
}
function renderUpgrade() {
  const box = el("section",undefined,"detail"), ack = consent("This is a disposable synthetic workspace. I reviewed the irreversible format upgrade.");
  box.append(el("h2","Upgrade this synthetic workspace"), el("p","Batch planning and external request history use a new storage format. This upgrade preserves cases, attempts and exact request history, and invalidates unused approvals. Older app versions cannot open it afterward. Name parts, email reachability and how you use each email are not guessed: every email starts as “Not sure” until you choose. Personal-store upgrades await storage review."), ack.label);
  box.append(button("Upgrade synthetic records",()=>run(async current=>{
    const result = await api("/api/upgrade",{version:record.version,acknowledged:ack.input.checked});
    if (current !== generation) return;
    const state=await api("/api/cases");
    if (current !== generation) return;
    record=result; workState=state;
    renderWorkspace(); message.textContent="Synthetic records upgraded. Review current residence and adult acknowledgment before preparing a request.";
  }),"primary"));
  return box;
}
const US_STATES = [["AL","Alabama"],["AK","Alaska"],["AZ","Arizona"],["AR","Arkansas"],["CA","California"],["CO","Colorado"],["CT","Connecticut"],["DE","Delaware"],["DC","District of Columbia"],["FL","Florida"],["GA","Georgia"],["HI","Hawaii"],["ID","Idaho"],["IL","Illinois"],["IN","Indiana"],["IA","Iowa"],["KS","Kansas"],["KY","Kentucky"],["LA","Louisiana"],["ME","Maine"],["MD","Maryland"],["MA","Massachusetts"],["MI","Michigan"],["MN","Minnesota"],["MS","Mississippi"],["MO","Missouri"],["MT","Montana"],["NE","Nebraska"],["NV","Nevada"],["NH","New Hampshire"],["NJ","New Jersey"],["NM","New Mexico"],["NY","New York"],["NC","North Carolina"],["ND","North Dakota"],["OH","Ohio"],["OK","Oklahoma"],["OR","Oregon"],["PA","Pennsylvania"],["RI","Rhode Island"],["SC","South Carolina"],["SD","South Dakota"],["TN","Tennessee"],["TX","Texas"],["UT","Utah"],["VT","Vermont"],["VA","Virginia"],["WA","Washington"],["WV","West Virginia"],["WI","Wisconsin"],["WY","Wyoming"],["AS","American Samoa"],["GU","Guam"],["MP","Northern Mariana Islands"],["PR","Puerto Rico"],["VI","U.S. Virgin Islands"]];
// Readiness for what is typed, before saving. Preparing always uses the saved information.
const PREVIEW_GROUPS = [
  ["Velum can prepare these", s => ["ready_to_prepare_email", "ready_for_local_preparation"].includes(s)],
  ["May apply to you once you add something", s => s === "needs_information"],
  ["Already requested", s => ["email_already_sent", "email_outcome_uncertain", "external_request_recorded"].includes(s)],
  ["Don’t apply where you live", s => ["route_not_available_in_jurisdiction", "route_not_available_in_country"].includes(s)]];
let previewTimer = null;
function renderPreview(box, result) {
  box.replaceChildren(el("h3", "What this unlocks"));
  if (!result.ready) { box.append(el("p", "Preview paused: " + result.problem, "muted")); return; }
  box.append(el("p", result.changed ? "Preview of unsaved changes. Preparing a request uses your saved information, so save to use these." : "Matches your saved information.", "muted"));
  let shown = 0;
  for (const [title, test] of PREVIEW_GROUPS) {
    const rows = result.rows.filter(r => test(r.state));
    if (!rows.length) continue;
    shown += rows.length;
    const list = el("ul");
    rows.forEach(r => {
      const li = el("li"); li.append(el("strong", r.name));
      if (r.missing.length && r.state === "needs_information") li.append(document.createTextNode(": " + r.missing.join("; ")));
      list.append(li);
    });
    box.append(el("h4", title), list);
  }
  const rest = result.rows.length - shown;
  if (rest) box.append(el("p", rest + " more give guidance only, or are paused while their official source is reviewed. See Coverage.", "muted"));
  box.append(el("p", "This shows which requests Velum can prepare, not whether a broker has your data. Velum hasn’t searched for you.", "muted"));
}
function previewDraft(box, draft, delay) {
  const go = () => {
    const current = generation;
    api("/api/preview", {profile: draft}).then(result => {if (current === generation) renderPreview(box, result);})
      .catch(() => {if (current === generation) box.replaceChildren(el("h3", "What this unlocks"), el("p", "The preview isn’t available right now. Saving still works.", "muted"));});
  };
  if (typeof setTimeout !== "function" || !delay) { go(); return; }
  clearTimeout(previewTimer); previewTimer = setTimeout(go, delay);
}
function senderNote() {
  const sender = (workState && workState.sender) || {};
  if (sender.kind === "gmail" && sender.account) return "Velum sends from your connected Gmail account, " + sender.account + ". Add it below as a current address you can receive mail at.";
  return "Each request shows which address it’s from before you approve it; if you send it yourself, send it from that address. Requests for work data use only an address you mark as Work.";
}
function stateCode(value) {
  const v = (value || "").trim().toLowerCase();
  const hit = US_STATES.find(([code, name]) => code.toLowerCase() === v || name.toLowerCase() === v);
  return hit ? hit[0] : "";
}
function renderProfile() {
  const box = el("section",undefined,"detail"), form=el("form",undefined,"profile-form");
  box.append(el("h2","My information"),el("p","Add only what you need. Saved edits invalidate unused approvals; historical disclosures keep their original values. Retiring a saved identifier removes it from future selections while preserving it locally."),el("p",sessionOnly()?"Saving keeps your edits for this session only; ending it erases them.":"Save before closing this page: closing it locks your encrypted record.","muted"));
  const draft = record.profile ? JSON.parse(JSON.stringify(record.profile)) : {schema:2,names:[newIdentifier("names")],emails:[],addresses:[],phones:[],birth_date:"",residence:{country:"",region:""},self_adult:false};
  if (!record.profile) draft.names[0].preferred=true;
  const original = new Set();
  if (record.profile) Object.keys(identityGroups).forEach(g=>record.profile[g].forEach(r=>original.add(r.id)));
  for (const [group,specs] of Object.entries(identityGroups)) {
    const section=el("section",undefined,"identity-group"), list=el("div");
    const singular={names:"name",emails:"email",addresses:"address",phones:"phone"}[group];
    section.append(el("h3",human(group)));
    if(group==="emails")section.append(el("p",senderNote(),"muted"));
    section.append(list);
    const add=button("Add another " + singular,()=>{
      if(draft[group].length>=10) return;
      draft[group].push(newIdentifier(group)); identityDirty=true; draw();
    });
    function draw() {
      list.replaceChildren(); add.disabled=draft[group].length>=10;
      draft[group].forEach((row,index)=>{
        const card=el("fieldset",undefined,"identity-entry"); card.append(el("legend",human(singular)+" "+(index+1)+(row.retired?" · retired":"")));
        const labels=choice("Status",(group==="names"?["current","former","alias"]:group==="addresses"?["current","past"]:["current","former"]).map(v=>[v,human(v)])); labels.input.value=row.label;
        labels.input.addEventListener("change",()=>{row.label=labels.input.value;if(row.label!=="current") row.preferred=false;identityDirty=true;draw();}); card.append(labels.label);
        for(const [key,title,limit] of specs){
          const type=key.endsWith("_date")?"date":group==="emails"&&key==="value"?"email":"text";
          const f=field(title,key,row[key],type,limit); f.input.required=(group==="names"&&key==="full_name")||(["emails","phones"].includes(group)&&key==="value");
          f.input.addEventListener("input",()=>{row[key]=f.input.value;identityDirty=true;}); card.append(f.label);
        }
        if(["emails","phones"].includes(group)){
          const reach=consent("I can receive verification messages here");reach.input.checked=row.reachable;
          reach.input.addEventListener("change",()=>{row.reachable=reach.input.checked;identityDirty=true;});card.append(reach.label);
        }
        if(group==="emails"){
          // Your own answer; Velum never guesses it from the address. Routes for work data use only professional.
          const use=choice("Type of address",[["unknown","Not sure"],["professional","Work"],["personal","Personal"]]);use.input.value=row.use||"unknown";
          use.input.addEventListener("change",()=>{row.use=use.input.value;identityDirty=true;});card.append(use.label);
        }
        const preferred=consent("Preferred current " + singular); preferred.input.checked=row.preferred; preferred.input.disabled=row.retired||row.label!=="current";
        preferred.input.addEventListener("change",()=>{draft[group].forEach(r=>r.preferred=false);row.preferred=preferred.input.checked;identityDirty=true;draw();});card.append(preferred.label);
        if(original.has(row.id)) card.append(button(row.retired?"Restore to selections":"Retire from selections",()=>{row.retired=!row.retired;if(row.retired)row.preferred=false;identityDirty=true;draw();}));
        else card.append(button("Remove unsaved " + singular,()=>{draft[group].splice(index,1);identityDirty=true;draw();}));
        list.append(card);
      });
    }
    section.append(add,el("p","Up to ten entries, including retired entries. Exact duplicates are kept separately and flagged after save.","muted"));draw();form.append(section);
  }
  const residence=el("fieldset"); residence.append(el("legend","Current residence · separate from historical addresses"));
  const countryField=field("Two-letter residence country","country",draft.residence.country,"text",2),regionSlot=el("div");
  function drawRegion(){
    // A US resident picks a state; any other country keeps free text.
    if(draft.residence.country.trim().toUpperCase()==="US"){
      const code=stateCode(draft.residence.region),pick=choice("Current state",[["","Choose your state"],...US_STATES]);
      if(draft.residence.region&&!code){const o=el("option",draft.residence.region+" (as saved)");o.value=draft.residence.region;pick.input.append(o);}
      pick.input.value=code||draft.residence.region;pick.input.addEventListener("change",()=>{draft.residence.region=pick.input.value;identityDirty=true;});
      regionSlot.replaceChildren(pick.label);
    }else{
      const f=field("Current state or region","region",draft.residence.region,"text",120);
      f.input.addEventListener("input",()=>{draft.residence.region=f.input.value;identityDirty=true;});regionSlot.replaceChildren(f.label);
    }
  }
  countryField.input.addEventListener("input",()=>{const was=draft.residence.country.trim().toUpperCase()==="US";draft.residence.country=countryField.input.value;identityDirty=true;if(was!==(draft.residence.country.trim().toUpperCase()==="US"))drawRegion();});
  drawRegion();residence.append(countryField.label,regionSlot);
  const birthday=field("Birth date · optional; selected only when a route needs it","birth_date",draft.birth_date,"date",10);
  birthday.input.addEventListener("input",()=>{draft.birth_date=birthday.input.value;identityDirty=true;});
  const adult=consent("I am an adult acting only for myself");adult.input.checked=draft.self_adult;
  adult.input.addEventListener("change",()=>{draft.self_adult=adult.input.checked;identityDirty=true;});form.append(residence,birthday.label,adult.label);
  submitForm(form,sessionOnly()?"Save for this session":"Save to my encrypted record",async current=>{
    const result=await api("/api/save",{profile:draft,version:record.version});
    if(current!==generation)return;
    record=result;identityDirty=false;submissionState=null;
    const state=await api("/api/cases");if(current!==generation)return;
    workState=state;renderWorkspace();message.textContent="Identity saved. No information sent; unused approvals require fresh review.";
  });
  (record.warnings||[]).forEach(w=>box.append(el("p",w,"notice")));
  const preview=el("aside",undefined,"preview-unlocks");preview.setAttribute("aria-live","polite");preview.append(el("h3","What this unlocks"),el("p","Checking…","muted"));
  for(const event of ["input","change","click"])form.addEventListener(event,()=>previewDraft(preview,draft,400));
  previewDraft(preview,draft,0);
  const layout=el("div",undefined,"profile-layout");layout.append(form,preview);
  box.append(layout);return box;
}
function changeView(view) {
  if(identityDirty&&!window.confirm("Discard unsaved identity changes? Save first to keep them."))return;
  identityDirty=false;workspaceView=view;pendingSend=null;actionLabel=null;message.textContent="";errorBox.hidden=true;
  if(view==="submissions")run(async current=>{
    const result=await api("/api/submissions");if(current!==generation)return;
    submissionState=result;renderWorkspace();
  });else renderWorkspace();
}
// History: one timeline for emails, forms you submit and requests made elsewhere. Each entry is what was
// prepared or reported at the time; values stay hidden until a row is opened.
const FIELD_LABELS = {full_name: "Name", first_name: "First name", last_name: "Last name", email: "Email address", us_state: "State of residence",
  country: "Country", region: "State or region", request_type: "Request type", phone: "Phone", address: "Address", city: "City",
  postal_code: "Postal code", birth_date: "Birth date"};
function sentence(text) { return text ? text.charAt(0).toUpperCase() + text.slice(1) : ""; }
function fieldLabel(key) { return FIELD_LABELS[key] || sentence(human(key)); }
function fieldLabels(keys) {
  const order = Object.keys(FIELD_LABELS), rank = k => order.includes(k) ? order.indexOf(k) : order.length;
  return [...keys].sort((a, b) => rank(a) - rank(b)).map(fieldLabel);
}
const EVENT_NAMES = {private_database_case: "Request added", candidate_found: "Listing added for review",
  match_confirmed: "You confirmed the listing is yours", match_rejected: "You said the listing isn’t yours",
  request_prepared: "Request prepared", request_approved: "Request approved", approval_revoked: "Approval withdrawn",
  handoff_started: "You opened the broker’s form", handoff_submitted: "You submitted the broker’s form",
  handoff_uncertain: "Not sure the form was submitted", handoff_not_disclosed: "Nothing was entered on the broker’s form",
  listing_check: "You checked the listing", review_date: "Review date set", note: "Evidence note",
  send_prepared: "Email prepared", send_approved: "Email approved", send_revoked: "Email approval withdrawn",
  send_dispatched: "Email handed to the sender", send_transport_accepted: "Your mail provider accepted the email",
  send_not_sent: "Your mail provider refused the email", send_uncertain: "Not sure the email was sent",
  send_user_sent: "You sent the email yourself", send_owner_unsure: "You weren’t sure the email went",
  send_user_confirmed_sent: "You found the email in your Sent folder", send_confirmed_by_broker_reply: "The broker’s reply shows the email arrived",
  send_not_found_in_sent: "You didn’t find the email in your Sent folder", send_duplicate_risk_acknowledged: "You accepted a possible duplicate request",
  external_submitted: "You reported it was submitted", external_uncertain: "Not sure it was submitted", external_not_sent: "Your evidence shows nothing was sent"};
const SOURCES = {local_action: "Done in Velum", user_reported: "Your report", transport_result: "Your mail provider’s answer", user_reported_external: "Your report"};
function eventName(kind) {
  if (EVENT_NAMES[kind]) return EVENT_NAMES[kind];
  if (kind.startsWith("broker_")) {
    const words = Object.fromEntries(REPLY_OPTIONS)[kind.slice(7)];
    return "Broker’s reply: " + (words ? words.charAt(0).toLowerCase() + words.slice(1) : human(kind.slice(7)));
  }
  return sentence(human(kind));
}
function eventList(events) {
  const list = el("ol", undefined, "timeline-events");
  [...events].reverse().forEach(e => {
    const li = el("li");
    li.append(el("time", localTime(e.at)), el("strong", eventName(e.kind)));
    if (e.note) li.append(el("p", e.note));
    if (e.result) li.append(el("p", "Observation: " + human(e.result)));
    li.append(el("span", SOURCES[e.provenance] || sentence(human(e.provenance || "")), "muted"));
    list.append(li);
  });
  return list;
}
function datedHistory(events) {
  const box = el("details", undefined, "history");
  box.append(el("summary", "Dated history · " + events.length + " event" + (events.length === 1 ? "" : "s")), eventList(events));
  return box;
}
function anyBrokerName(id) {
  const outside = (workState.workflow?.external_brokers || []).find(b => b.id === id);
  return outside && !(workState.catalog || []).some(r => r.id === id) ? outside.name : brokerName(id);
}
// A form you submit yourself: its attempt, or else its request, in plain words with a status tone.
const FORM_STATUS = {prepared: ["Ready for your review", "review"], approved: ["Approved, form not opened yet", "review"],
  expired: ["Approval expired · review again", "action"], invalidated: ["Something changed · prepare it again", "action"],
  revoked: ["Approval withdrawn", "waiting"], source_review_due: ["Paused · official source under review", "waiting"],
  not_prepared: ["Not prepared yet", "review"], consumed: ["Form opened", "waiting"],
  handoff_started: ["Form opened · outcome unknown", "uncertain"], uncertain: ["Not sure it was submitted", "uncertain"],
  submitted_user_reported: ["Submitted · your report", "waiting"], closed_without_disclosure_user_reported: ["Nothing entered · closed", "done"]};
const EXTERNAL_STATUS = {submitted: ["Submitted · your report", "waiting"], uncertain: ["Not sure it was submitted", "uncertain"], not_sent: ["Not sent · your evidence", "done"]};
function whenKey(value) {
  // Dates without a time are a local day; timestamps are UTC. Both sort as moments.
  if (!value) return 0;
  const t = new Date(/^\d{4}-\d{2}-\d{2}$/.test(value) ? value + "T12:00:00" : value).getTime();
  return isNaN(t) ? 0 : t;
}
function localDay(value) {
  if (!value || /^\d{4}-\d{2}-\d{2}$/.test(value)) return value || "";
  const d = new Date(value);
  return isNaN(d.getTime()) ? value.slice(0, 10) : [d.getFullYear(), String(d.getMonth() + 1).padStart(2, "0"), String(d.getDate()).padStart(2, "0")].join("-");
}
function searchText(values) {
  // Only the values themselves, never field names, are searched.
  const out = [], walk = v => { if (v == null) return; if (typeof v === "object") Object.values(v).forEach(walk); else out.push(String(v)); };
  walk(values); return out.join("\n").toLocaleLowerCase();
}
function historyRows() {
  const s = submissionState || {}, rows = [], cases = new Map((workState.cases || []).map(c => [c.id, c]));
  const groups = new Map(((workState.attention || {}).items || []).map(a => [a.case_id, a.group]));
  for (const e of s.entries || []) {
    const attempt = e.attempts.at(-1)?.state || "", uncertain = ["handoff_started", "uncertain"].includes(attempt) || Boolean(e.legacy_attempt_alignment_unknown);
    rows.push({kind: "manual", type: "Form you submit", data: e, broker: e.broker, case_id: e.case_id, when: e.request.prepared_at, current: e.current,
      version: e.revision, uncertain, due: e.current && e.due, review_on: e.review_on, group: e.current ? groups.get(e.case_id) : null,
      ...(() => { const key = attempt || (e.current ? e.request_status : ""), [status, tone] = !key ? ["Earlier version", "waiting"] : FORM_STATUS[key] || [sentence(human(key)), "waiting"];
        return {status, tone: uncertain ? "uncertain" : tone}; })(),
      values: [e.request.snapshot.fields, e.request.snapshot.purpose]});
  }
  for (const e of s.emails || []) {
    // An earlier email that was sent, refused or uncertain keeps saying so; only an unused one is just "earlier".
    const [words, tone] = e.current || e.status !== "superseded" ? emailStatus(e.status) : ["Earlier version", "waiting"], c = cases.get(e.case_id);
    rows.push({kind: "email", type: "Email", data: e, broker: e.broker, case_id: e.case_id, when: e.dispatched_at || e.prepared_at, current: e.current,
      version: e.revision, uncertain: e.status === "uncertain", due: Boolean(e.current && c?.due), review_on: e.current ? c?.review_on : null,
      group: e.current ? groups.get(e.case_id) : null, status: words, tone, values: [e.message]});
  }
  for (const e of workState.workflow?.external || []) {
    const [words, tone] = EXTERNAL_STATUS[e.state] || [sentence(human(e.state)), "waiting"];
    rows.push({kind: "external", type: "Made elsewhere", data: e, broker: e.broker, case_id: null, when: e.date, current: true, version: 1,
      uncertain: e.state === "uncertain", due: false, review_on: null, group: {uncertain: "do", submitted: "waiting"}[e.state] || null,
      status: words, tone, values: [e.purpose, e.history.map(h => h.note)]});
  }
  return rows;
}
function manualContent(e, content) {
  const req = e.request, snap = req.snapshot;
  content.append(el("p", snap.purpose), el("p", "Where: " + snap.route.destination, "mono"), el("p", "How: " + sentence(human(snap.route.method))),
    el("p", "Prepared " + localTime(req.prepared_at) + (req.approval?.at ? " · approved " + localTime(req.approval.at) : " · not approved")));
  const table = el("table", undefined, "email-table");
  for (const [key, value] of Object.entries(snap.fields)) { const tr = el("tr"); tr.append(el("th", fieldLabel(key)), el("td", value)); table.append(tr); }
  content.append(table);
  const saved = fieldLabels(Object.keys(snap.identifiers || {}));
  content.append(el("p", saved.length ? "Chosen from My information: " + saved.join(", ") : "Values entered for this request; none were chosen from My information.", "muted"));
  e.attempts.forEach(a => content.append(el("p", "Broker’s form opened " + localTime(a.started_at) + " · " + (FORM_STATUS[a.state] || [human(a.state)])[0])));
  if (e.legacy_attempt_alignment_unknown) content.append(el("p", "This older attempt can’t be matched to one exact version of the request. Check the dated history; don’t assume a second submission.", "notice"));
  if (snap.listing_url) content.append(el("p", "Listing: " + snap.listing_url, "mono"));
  if (e.current) content.append(el("p", "Broker’s reply: " + (e.broker_response === "unknown" ? "none recorded" : human(e.broker_response)) +
    (e.visibility !== "not_applicable" ? " · listing: " + human(e.visibility) + (e.visibility_at ? " on " + localTime(e.visibility_at) : "") : "") +
    " · next review: " + (e.review_on ? localTime(e.review_on) : "not set")));
  content.append(el("p", e.next_step, "next-step"));
}
function emailContent(e, content) {
  const c = e.contract;
  content.append(el("p", c ? c.purpose + " · " + c.entity : "Recorded before contract details were kept with each email; the exact message below is the record."),
    emailTable(e.message), el("pre", e.message.body),
    el("p", "Chosen from My information: " + fieldLabels(e.selected).join(", "), "muted"),
    el("p", "Prepared " + localTime(e.prepared_at) + " · " + (e.approved_at ? "approved " + localTime(e.approved_at) : "not approved") + " · " +
      (e.dispatched_at ? "handed to the sender " + localTime(e.dispatched_at) : "not sent")));
  if (c?.jurisdiction_basis) content.append(el("p", "Why the broker offers this: " + c.jurisdiction_basis, "muted"));
  content.append(technicalDetails({...e, contract_id: e.contract_id || c?.id, contract_version: e.contract_version || c?.version, approval: e.approved_at ? {at: e.approved_at} : null}), el("p", e.next_step, "next-step"));
}
function externalContent(e, content) {
  content.append(el("p", e.purpose), el("p", "What was sent and what was approved are unknown: this is your report, not a verified receipt.", "muted"),
    el("p", "Request date: " + localTime(e.date) + (e.date_precision === "approximate" ? " (approximate)" : "")),
    eventList(e.history.map(h => ({...h, kind: "external_" + h.state}))));
  if (e.state === "uncertain") {
    const form = el("form", undefined, "profile-form"), result = choice("What does your evidence show?", [["submitted", "It was submitted"], ["not_sent", "Nothing was sent or disclosed"]]);
    const note = field("Evidence for this correction", "external-reconcile", "", "textarea"); note.input.required = true;
    form.append(result.label, note.label); submitForm(form, "Record what you found", current => flowCommand("reconcile", {id: e.id, state: result.input.value, note: note.input.value}, current));
    content.append(form);
  }
}
function renderSubmissions() {
  const box = el("section", undefined, "detail"), filters = el("div", undefined, "history-filters"), rows = el("div", undefined, "timeline");
  box.append(el("h2", "History"), el("p", "Every request in one place: emails, forms you submit yourself and requests you made elsewhere. Each entry is exactly what was prepared or reported at the time; changing your information later never rewrites it. Values stay hidden until you open an entry."));
  const all = historyRows();
  const brokers = [...new Set(all.map(r => r.broker))].map(id => [id, anyBrokerName(id)]).sort((a, b) => a[1].localeCompare(b[1]));
  const broker = choice("Broker", [["", "All brokers"], ...brokers]);
  const type = choice("Type", [["", "All requests"], ["email", "Emails"], ["manual", "Forms you submit"], ["external", "Made elsewhere"]]);
  const state = choice("Status", [["", "Any status"], ["do", "You need to do"], ["review", "Ready to review"], ["waiting", "Waiting on the broker"], ["recorded", "Outcome recorded"], ["uncertain", "Uncertain"], ["due", "Review date reached"], ["earlier", "Earlier versions"]]);
  const start = field("From", "from", "", "date"), end = field("Through", "through", "", "date"), search = field("Search, including hidden values", "search", "", "search", 200);
  const sort = choice("Sort", [["newest", "Newest first"], ["oldest", "Oldest first"], ["due", "Next review date"]]);
  const controls = [broker, type, state, start, end, search, sort]; controls.forEach(c => filters.append(c.label));
  function draw() {
    rows.replaceChildren();
    const wanted = {do: r => r.group === "do", review: r => r.group === "review", waiting: r => r.group === "waiting", recorded: r => r.group === "recorded",
      uncertain: r => r.uncertain, due: r => r.due, earlier: r => !r.current};
    const q = search.input.value.toLocaleLowerCase();
    const visible = all.filter(r => {
      const day = localDay(r.when);
      return (!broker.input.value || r.broker === broker.input.value) && (!type.input.value || r.kind === type.input.value) &&
        (!state.input.value || wanted[state.input.value](r)) && (!start.input.value || day >= start.input.value) && (!end.input.value || day <= end.input.value) &&
        (!q || searchText([r.values, anyBrokerName(r.broker)]).includes(q));
    });
    visible.sort((a, b) => sort.input.value === "oldest" ? whenKey(a.when) - whenKey(b.when) :
      sort.input.value === "due" ? (a.review_on || "9999").localeCompare(b.review_on || "9999") || whenKey(b.when) - whenKey(a.when) : whenKey(b.when) - whenKey(a.when));
    if (!submissionState) rows.append(el("p", "Loading your history…", "muted"));
    else if (!all.length) rows.append(el("p", "Nothing here yet. Requests you prepare, and ones you record from elsewhere, appear here.", "notice"));
    else if (!visible.length) rows.append(el("p", "No entries match these filters.", "notice"));
    for (const r of visible) {
      const details = el("details", undefined, "history timeline-row"), summary = el("summary"), content = el("div"), shown = el("span", "Values hidden", "muted");
      const when = r.when ? localTime(r.when) + (r.kind === "external" && r.data.date_precision === "approximate" ? " (approx.)" : "") : "No date";
      summary.append(el("time", when), el("strong", anyBrokerName(r.broker)), el("span", r.type + (r.version > 1 || !r.current ? " · version " + r.version : ""), "muted"), el("span", r.status, "pill tone-" + r.tone), shown);
      details.append(summary, content);
      details.addEventListener("toggle", () => {
        shown.textContent = details.open ? "Values shown" : "Values hidden";
        content.replaceChildren(); if (!details.open) return;
        ({manual: manualContent, email: emailContent, external: externalContent})[r.kind](r.data, content);
        const events = r.case_id && submissionState?.histories?.[r.case_id];
        if (events) content.append(datedHistory(events));
        if (r.case_id) content.append(button("Open in Your requests", () => { selectedCase = r.case_id; changeView("queue"); }));
      });
      rows.append(details);
    }
  }
  controls.forEach(c => { c.input.addEventListener("input", draw); c.input.addEventListener("change", draw); });
  draw(); box.append(filters, rows);
  if (workState.workflow) box.append(renderExternal());
  return box;
}

function link(label, url) {
  const a = el("a", label); a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer"; return a;
}
const LEVELS = {research_only: "Research only", guided_manual: "Guided manual", local_preparation: "Local preparation",
  automated_simulation: "Automated simulation", pilot_tested: "Pilot tested", maintained_operation: "Maintained operation"};
function readiness(r) {
  return r.readiness === "manual_preparation" ? "local draft available" : r.readiness === "owner_email" ? "automated simulation; no real broker request is sent in this build" : "guidance and tracking";
}
const LEVEL_HELP = {research_only: "Researched only: official sources and gaps are recorded, but Velum can’t prepare a request.",
  guided_manual: "Official guidance: you do every step yourself.",
  local_preparation: "Velum prepares the exact request from your information; you submit the broker’s form yourself.",
  automated_simulation: "Velum can send the exact email you approve, but in this build only to a local test mail service.",
  pilot_tested: "Tried for real once, with the owner’s explicit authorization.", maintained_operation: "Used for real and kept up to date."};
const FOR_YOU = [
  [["ready_to_prepare_email", "ready_for_local_preparation"], "Available to you", "review"],
  [["needs_information"], "May apply once you add something", "action"],
  [["email_already_sent", "email_outcome_uncertain", "external_request_recorded"], "Already requested", "waiting"],
  [["route_not_available_in_jurisdiction", "route_not_available_in_country"], "Doesn’t apply where you live", "waiting"],
  [["source_review_due"], "Paused while its source is reviewed", "waiting"],
  [["guidance_only"], "Guidance only: you do the steps", "waiting"],
  [["research_only"], "Not supported yet", "waiting"]];
function forYou(state) { return FOR_YOU.find(([states]) => states.includes(state)) || null; }
function capabilityMatrix(catalog, plan) {
  const box = el("section", undefined, "broker-guide"), list = el("div", undefined, "route-matrix"), mine = new Map((plan || []).map(p => [p.broker, p]));
  box.append(el("h2", "Capability matrix"), el("p", "Each broker, purpose, jurisdiction and method is its own route. Automated simulation means the sending path passes tests against a local fake provider only: no real broker request has been sent and no route is pilot tested. Research-only rows record sources and gaps; they are not supported routes.", "muted"));
  if (plan) {
    const ready = plan.filter(p => forYou(p.state)?.[1] === "Available to you").length;
    box.append(el("p", ready ? ready + " route" + (ready === 1 ? " is" : "s are") + " available to you now, from your saved information. They’re highlighted below." : "No route is ready for you yet. Each one says what it would need."));
  }
  const card = (name, level, rows, p) => {
    const you = p ? forYou(p.state) : null, item = el("article", undefined, "route-card" + (you && you[1] === "Available to you" ? " eligible" : "")), head = el("div", undefined, "attention-head");
    head.append(el("h3", name), el("span", LEVELS[level] || human(level), "pill level"));
    item.append(head, el("p", LEVEL_HELP[level] || "", "muted"));
    if (you) { const line = el("p", undefined, "for-you"); line.append(el("span", "For you:", "strong"), el("span", you[1], "pill tone-" + you[2])); item.append(line); }
    if (p && p.state === "needs_information" && p.missing.length) item.append(el("p", "What it needs: " + p.missing.join("; ")));
    const dl = el("dl"); rows.forEach(([k, v]) => { if (v) dl.append(el("dt", k), el("dd", v)); }); item.append(dl);
    return item;
  };
  for (const r of catalog) {
    const f = r.freshness || {};
    list.append(card(r.name, r.capability || "research_only", [["Who it covers", r.covers], ["Method and purpose", human(r.method) + " · " + r.purpose],
      ["Source checked", f.checked || r.checked], ["Review by", f.review_by], ["Evidence", f.fresh === false ? f.reason : "Within the 30-day review window"]], mine.get(r.id)));
  }
  for (const p of (plan || []).filter(p => p.state === "research_only" && !catalog.some(r => r.id === p.broker))) {
    list.append(card(p.name, "research_only", [["Who it covers", "Not established"], ["Evidence", "Route contract, eligibility and execution remain unimplemented. See the coverage map."]], p));
  }
  box.append(list); return box;
}
function requirementsGuide(r) {
  const guide = r.requirements, box = el("section", undefined, "broker-guide"), f = r.freshness || {};
  box.append(el("h3", r.name + " · " + readiness(r)),
    el("p", guide.scope), el("p", guide.next_action, "next-step"),
    el("p", guide.route_evidence, "muted"),
    el("p", "Research record: " + r.checked + (r.source_fresh && f.fresh !== false ? " · within the 30-day review window" : " · review due; do not rely on this as current guidance"), "muted"));
  if (f.fresh === false) box.append(el("p", f.reason, "notice"));
  const table = el("table"), head = el("thead"), tr = el("tr"), body = el("tbody");
  tr.append(el("th", "Information / step"), el("th", "Broker requirement"), el("th", "Evidence and what to do")); head.append(tr);
  guide.inputs.forEach(f => {
    const row = el("tr"), detail = el("td"), status = el("td", f.need === "unknown" ? "Not established" : human(f.need));
    detail.append(el("strong", human(f.basis)), el("p", f.note));
    f.sources.forEach((url, i) => {detail.append(link("Source " + (i + 1) + " ↗", url), document.createTextNode(" "));});
    row.append(el("th", f.label), status, detail); body.append(row);
  });
  table.append(head, body); const scroll = el("div", undefined, "table-scroll"); scroll.append(table);
  box.append(el("h4", "What the broker asks for"), el("p", "A visible field is not proof it is mandatory or optional. An unknown requirement must be checked before disclosure. No broker's server acceptance has been tested."), scroll);
  for (const [title, text] of [["Verification", guide.verification], ["What completion means", guide.completion], ["Follow-up timing", guide.follow_up], ["Manual alternative", guide.fallback]]) {
    box.append(el("h4", title), el("p", text));
  }
  const gaps = el("ul"); guide.gaps.forEach(gap => gaps.append(el("li", gap)));
  box.append(el("h4", "Still to confirm"), gaps);
  for (const [title, values] of [["Evidence to keep after a request", guide.acceptance], ["Requirements for a live pilot", guide.pilot_checks]]) {
    const details = el("details", undefined, "history"), list = el("ol"); values.forEach(v => list.append(el("li", v)));
    details.append(el("summary", title), list); box.append(details);
  }
  box.append(el("p", r.automation, "muted"), el("p", "Official guidance opens only when you click. The link carries no identity; the external site can still receive IP/browser information. Inspect it before entering data.", "muted"), link("Open official guidance ↗", r.destination));
  return box;
}
async function loadRequirements() {
  const target = document.querySelector("#broker-requirements");
  try {
    const {brokers} = await api("/api/brokers");
    const select = choice("Choose a broker", brokers.map(r => [r.id, r.name])), content = el("div");
    select.input.id = "requirements-broker";
    const render = () => content.replaceChildren(requirementsGuide(brokers.find(r => r.id === select.input.value)));
    select.input.addEventListener("change", render); render();
    target.replaceChildren(el("p", "Read this guide without creating or unlocking a profile. Everything here is public research stored with the app."), capabilityMatrix(brokers), select.label, content);
  } catch (_) {target.replaceChildren(el("p", "The requirements guide could not load. Reload to retry; do not assume requirements are verified."));}
}
function field(title, name, value = "", type = "text", limit = 1500) {
  const label = el("label", title), input = el(type === "textarea" ? "textarea" : "input");
  if (type !== "textarea") input.type = type;
  input.name = name; input.value = value; input.maxLength = limit; input.autocomplete = "off"; input.spellcheck = false;
  label.append(input); return {label, input};
}
function choice(title, options) {
  const label = el("label", title), input = el("select");
  for (const [value, name] of options) {const o = el("option", name); o.value = value; input.append(o);}
  label.append(input); return {label, input};
}
function consent(title) {
  const label = el("label", undefined, "consent"), input = el("input"); input.type = "checkbox";
  label.append(input, document.createTextNode(title)); return {label, input};
}
function submitForm(form, title, work) {
  const b = el("button", title, "primary"); b.type = "submit"; form.append(b);
  form.addEventListener("submit", e => {e.preventDefault(); actionLabel = title; run(work);}); return b;
}
async function command(c, action, data, current) {
  const result = await api("/api/cases/command", {id:c.id,version:c.version,action,data});
  if (current !== generation) return;
  workState = result; renderWorkspace();
  message.textContent = result.dry_run_result || (sessionOnly() ? "Saved for this session. Nothing was sent." : "Saved in your encrypted record. Nothing was sent.");
}
const human = value => ({consumed:"approved handoff used",submitted_user_reported:"submitted · reported by you",
  handoff_started:"handoff open · outcome unknown",source_review_due:"official source review due"}[value] || value.replaceAll("_", " "));
async function flowCommand(action,data,current) {
  const result=await api("/api/workflow",{version:workState.workflow.version,profile_version:record.version,action,data});
  if(current!==generation)return;
  if(result.locked){wipe();renderLocked();message.textContent="The vault locked while sending. Results are recorded at your next unlock.";return;}
  workState=result;submissionState=null;
  if(workspaceView==="submissions"){
    const history=await api("/api/submissions");if(current!==generation)return;submissionState=history;
  }
  renderWorkspace();
  message.textContent=result.prepare_results?prepareSummary(result):result.dispatch_results?(result.dispatch_results.length?"Sending finished: "+result.dispatch_results.map(r=>{const c=(result.cases||[]).find(x=>x.id===r.case_id),name=c&&(result.catalog||[]).find(x=>x.id===c.broker)?.name;return (name?name+" ":"")+human(r.outcome);}).join(", ")+". Review each case.":"No approved emails were ready to send."):"Local workflow saved. No request was transmitted.";
}
async function executionCommand(c,action,data,current) {
  const result=await api("/api/execution",{id:c.id,version:c.version,action,data});
  if(current!==generation)return;
  if(result.locked){wipe();renderLocked();message.textContent="The vault locked while sending. The result is recorded at your next unlock.";return;}
  workState=result;renderWorkspace();
  message.textContent=result.send_result?"Send result: "+human(result.send_result.outcome)+". Review the case for what it means.":action==="approve"?"Approved. Nothing has been sent.":"Saved locally. Nothing was sent.";
}
function prepareSummary(result) {
  const done = result.prepare_results.filter(r => r.outcome === "prepared").length;
  const skipped = result.prepare_results.filter(r => r.outcome !== "prepared");
  const name = id => brokerName(((result.cases || []).find(c => c.id === id) || {}).broker);
  if (!result.prepare_results.length) return "No emails were ready to prepare.";
  return (done ? "Prepared " + done + " email" + (done === 1 ? "" : "s") + ". Nothing was sent or approved." : "No email was prepared.") +
    (skipped.length ? " Not prepared: " + skipped.map(r => name(r.case_id) + " (" + r.reason + ")").join("; ") + "." : "");
}
const REVIEWABLE = ["email_prepared", "email_expired"];
function batchCases(test) {
  const f = workState.workflow;
  return (workState.cases || []).filter(c => f.case_ids.includes(c.id) && c.execution && test(c));
}
function startReview() {
  const order = (workState.workflow?.items || []).filter(i => REVIEWABLE.includes(i.state)).map(i => i.id);
  stepper = {order, done: {}}; workspaceView = "approve"; pendingSend = null; renderWorkspace();
}
function sendTo(onSend) {
  // The batch's Send button: ask how to send first, then confirm in the page.
  const sender = workState.sender || {};
  if (!sendMethod || (sendMethod === "velum" && !sender.broker_sending)) { changeView("send-choice"); return; }
  if (sendMethod === "self") { onSend(); return; }
  pendingSend = "batch"; renderWorkspace();
}
function sendConfirmation(cases, onSend) {
  // Replaces a browser dialog: the exact recipients, in the page, next to the button that sends.
  const box = el("section", undefined, "confirm-send"), n = cases.length;
  box.setAttribute("role", "group"); box.setAttribute("aria-label", "Confirm sending");
  const froms = [...new Set(cases.map(c => c.execution.message.from))];
  const heading = el("h3", n === 1 ? "Send this email?" : "Send these " + n + " emails?");
  focusSoon(heading);
  box.append(heading,
    el("p", "Velum sends " + (n === 1 ? "it" : "each one") + " once, exactly as you approved it" + (froms.length === 1 ? ", from " + froms[0] : "") + ". A message handed to your mail provider can’t be recalled."));
  const table = el("table"), head = el("tr");
  ["Broker", "To", ...(froms.length > 1 ? ["From"] : [])].forEach(t => head.append(el("th", t))); table.append(head);
  for (const c of cases) {
    const row = el("tr"), m = c.execution.message;
    row.append(el("td", brokerName(c.broker)), el("td", m.to), ...(froms.length > 1 ? [el("td", m.from)] : []));
    table.append(row);
  }
  const scroll = el("div", undefined, "table-scroll"); scroll.append(table); box.append(scroll);
  if (n > 1) box.append(el("p", "Pausing stops the rest, but not a message already handed over. If a send is uncertain, Velum never tries again on its own.", "muted"));
  const actions = el("div", undefined, "actions"), go = button(n === 1 ? "Send 1 email" : "Send " + n + " emails", onSend, "primary");
  actions.append(go, button("Cancel", () => { pendingSend = null; renderWorkspace(); }));
  box.append(actions);
  return box;
}
function focusSoon(node) {
  // After a re-render, move keyboard and screen-reader focus to the new heading.
  node.setAttribute("tabindex", "-1");
  if (typeof setTimeout !== "function") return;
  setTimeout(() => { if (node.isConnected) { node.focus?.(); node.scrollIntoView?.({block: "nearest"}); } }, 0);
}
// Routes grouped by what you can do; the titles match the readiness preview in My information.
const ROUTE_GROUPS = [
  ...PREVIEW_GROUPS.slice(0, 3),
  ["You do these yourself, with Velum’s guidance", s => s === "guidance_only"],
  ["Paused while the official source is reviewed", s => s === "source_review_due"]];
const ROUTE_HIDDEN = [
  ["Don’t apply where you live", s => ["route_not_available_in_jurisdiction", "route_not_available_in_country"].includes(s)],
  ["Not supported yet", s => s === "research_only"]];
function routeNote(p) {
  return p.route_issue || p.missing.join("; ") || ({email_already_sent: "An email to this broker was sent; see its case.",
    email_outcome_uncertain: "An earlier email’s outcome is uncertain; settle it in its case before sending another.",
    external_request_recorded: "You recorded a request made outside Velum.",
    ready_to_prepare_email: "Velum can prepare the exact email. You approve it on its own.",
    ready_for_local_preparation: "Velum can prepare the exact request. You approve it, then submit the broker’s form yourself.",
    research_only: "Researched only. Velum can’t prepare a request yet.",
    guidance_only: "Official guidance is available; there is no prepared request."})[p.state] ||
    (p.drop_overlap ? "A recorded DROP request may overlap; review before preparing." : "Review each exact request before it goes anywhere.");
}
function routeTable(rows) {
  const table = el("table", undefined, "route-table"), head = el("tr");
  ["Route", "What happens next"].forEach(t => head.append(el("th", t))); table.append(head);
  rows.forEach(p => { const row = el("tr"); row.append(el("th", p.name), el("td", routeNote(p))); table.append(row); });
  const scroll = el("div", undefined, "table-scroll"); scroll.append(table); return scroll;
}
function routeGroups(plan) {
  const box = el("details", undefined, "history"), used = new Set();
  box.append(el("summary", "All routes · what your saved information makes possible"));
  for (const [title, test] of ROUTE_GROUPS) {
    const rows = plan.filter(p => !used.has(p) && test(p.state));
    if (!rows.length) continue;
    rows.forEach(p => used.add(p));
    box.append(el("h4", title + " · " + rows.length), routeTable(rows));
  }
  const other = plan.filter(p => !used.has(p) && !ROUTE_HIDDEN.some(([, test]) => test(p.state)));
  if (other.length) { other.forEach(p => used.add(p)); box.append(el("h4", "Other routes · " + other.length), routeTable(other)); }
  for (const [title, test] of ROUTE_HIDDEN) {
    const rows = plan.filter(p => !used.has(p) && test(p.state));
    if (!rows.length) continue;
    const more = el("details", undefined, "history");
    more.append(el("summary", title + " · " + rows.length), routeTable(rows)); box.append(more);
  }
  return box;
}
function renderBatch() {
  const f=workState.workflow,box=el("section",undefined,"detail");
  box.append(el("h2","Your requests"),el("p","One saved identity feeds every available route. Each request needs its own review and approval, and nothing is sent until you choose to send it. Owner-email routes go by email; other routes use manual handoffs."));
  const sender=workState.sender||{};
  box.append(el("p",senderBanner(sender),"notice"));
  if(f.drop.state==="eligible_self_reported"){
    box.append(el("h3","Start with California DROP"),el("p","Your saved current residence is California. DROP verifies eligibility itself and requires its own deletion profile. Complete those steps directly; Velum cannot submit or transfer your identity to DROP."),link("Open official California DROP ↗",f.drop.url),button("Record a DROP request already made",()=>changeView("submissions")));
  }else if(f.drop.state==="needs_residence")box.append(el("p","Add your current country and state in My information to check DROP eligibility. Historical addresses do not establish residence."));
  else box.append(el("p","DROP is for California residents. Your other broker routes remain available according to their own eligibility; California-only research does not establish eligibility elsewhere."));
  const actions=el("div",undefined,"actions");
  const preparable=(f.preparable||[]).length,reviewable=f.items.filter(i=>REVIEWABLE.includes(i.state)).length;
  const approvedCases=batchCases(c=>c.execution_status==="approved"),approved=approvedCases.length;
  const plural=n=>n===1?"":"s";
  if(preparable)actions.append(button("Prepare all ready emails ("+preparable+")",()=>run(async current=>{
    await flowCommand("prepare_emails",{},current);
    if(current===generation&&workState.workflow&&workState.workflow.items.some(i=>REVIEWABLE.includes(i.state)))startReview();
  }),"primary"));
  if(reviewable)actions.append(button("Review and approve "+reviewable+" email"+plural(reviewable),startReview,preparable?"secondary":"primary"));
  if(f.case_ids.length&&!f.paused&&approved)actions.append(button("Send "+approved+" approved email"+plural(approved),()=>sendTo(()=>{
    selectedCase=approvedCases[0].id;renderWorkspace();message.textContent="Send each approved email from your mail app, then tell Velum.";
  }),preparable||reviewable?"secondary":"primary"));
  actions.append(button(f.case_ids.length?"Refresh my requests":"Build my requests",()=>run(current=>flowCommand("plan",{},current)),f.case_ids.length?"secondary":"primary"));
  if(f.case_ids.length)actions.append(button(f.paused?"Resume sending":"Pause sending",()=>run(current=>flowCommand(f.paused?"resume":"pause",{},current))));
  box.append(actions);
  if(pendingSend==="batch"&&approved&&!f.paused)box.append(sendConfirmation(approvedCases,()=>{
    const fingerprints=approvedCases.map(c=>c.execution.fingerprint);
    run(current=>{pendingSend=null;return flowCommand("dispatch",{fingerprints},current);});
  }));
  box.append(el("p",f.case_ids.length?(f.paused?"Paused: nothing is sent until you resume. Pausing can’t stop work already begun on an external page.":"Ready: each email still needs your approval, and nothing goes out until you press Send.")+" "+f.case_ids.length+" request"+plural(f.case_ids.length)+".":"Nothing here yet. Building your requests adds every route your saved information makes available. It prepares and approves nothing.","muted"));
  const words=state=>state.startsWith("email_")?emailStatus(state.slice(6))[0]:human(state);
  for(const [state,count] of Object.entries(f.counts))box.append(el("p",count+" · "+words(state)));
  const next=f.items.find(i=>["needs_match_confirmation","needs_exact_approval","ready_for_manual_handoff","ready_for_local_preparation","ready_to_prepare_email","email_prepared","email_uncertain"].includes(i.state));
  if(next)box.append(button("Review next ready case",()=>{selectedCase=next.id;renderWorkspace();}));
  const routes=routeGroups(f.plan);routes.open=!f.case_ids.length;box.append(routes);return box;
}
function renderExternal() {
  const f=workState.workflow,box=el("section",undefined,"external-record");
  box.append(el("h3","Record a request made elsewhere"),el("p","Record requests you made outside Velum, including DROP. They appear in the timeline above. Dates and outcomes are your report; what was sent and approved stays unknown. An active request recorded here blocks another one from Velum to the same broker, and a DROP request prompts an overlap review."));
  const add=el("details",undefined,"history"),form=el("form",undefined,"profile-form");
  add.append(el("summary","Record a request made elsewhere"));
  const broker=choice("Broker or service",f.external_brokers.map(b=>[b.id,b.name]));
  const purpose=field("Purpose of the original request","external-purpose","","text",200),when=field("Request date","external-date","","date",10);
  const precision=choice("Date certainty",[["exact","Exact date"],["approximate","Approximate date"]]);
  const state=choice("What is known",[["uncertain","Uncertain whether submitted"],["submitted","Submitted, based on my evidence"]]);
  const note=field("Evidence note · no verification links, codes or documents","external-note","","textarea");
  const self=consent("This request was only for me.");purpose.input.required=when.input.required=note.input.required=true;
  form.append(broker.label,purpose.label,when.label,precision.label,state.label,note.label,self.label);
  submitForm(form,"Save this record",current=>flowCommand("external",{broker:broker.input.value,purpose:purpose.input.value,date:when.input.value,date_precision:precision.input.value,state:state.input.value,note:note.input.value,self_only:self.input.checked},current));
  add.append(form);box.append(add);
  return box;
}

function renderWorkspace() {
  setRoot();
  if (keyNotice) {
    const warning = el("p", keyNotice, "notice"); warning.setAttribute("role", "alert");
    root.append(warning);
  }
  const sessionOnly=status&&status.store==="session";
  renderHeader();
  try { renderView(sessionOnly); } finally { placeBanners(); }
}
function renderView(sessionOnly) {
  if (workState && workState.recovery) {
    const r = workState.recovery;
    root.append(el("p", "Restored history from " + r.snapshot_at + ". " + (r.reconciled_at ? "Reconciliation recorded; historical outcomes remain dated reports." : "History may omit later requests. Record missing or uncertain activity, then use recovery reconcile. New request approval and handoffs are blocked."), "notice"));
  }
  if(workspaceView==="end"){root.append(renderEnd());return;}
  if(workspaceView==="send-choice"){root.append(renderSendChoice());return;}
  if(workspaceView==="approve"&&record.profile&&workState.workflow){root.append(renderApprove());return;}
  if(workspaceView==="convert"){root.append(renderConvert());return;}
  if(workspaceView==="help"){const box=el("section",undefined,"detail help");box.append(el("h2","Help"),el("p","The guide, each broker’s requirements and California’s free DROP service. This is public research that ships with Velum; nothing here reads or sends your information."));guides.forEach(g=>box.append(g));root.append(box);return;}
  if(workspaceView==="settings"){
    const recoveryHelp = el("section", "", "card");
    recoveryHelp.append(el("h2", "Encrypted backup and recovery"), el("p", "Synthetic-only command-line recovery is available. Stop Velum first. Run velum recovery --help for export, restore and reconciliation. Use a separate backup passphrase; losing it makes that backup unrecoverable. Restore requires a new directory and does not restore sending-account grants. Local deletion does not delete backup copies."));
    root.append(recoveryHelp);

    const reload=el("section",undefined,"detail");
    reload.append(el("h2","Privacy & settings"),el("p","Reload reads your information and requests again from Velum. Unsaved edits are discarded."),button("Reload saved records",()=>{
      if(identityDirty&&!window.confirm("Discard unsaved identity changes and reload?"))return;
      run(async current=>{const p=await api("/api/profile"),state=await api("/api/cases");if(current!==generation)return;record=p;workState=state;identityDirty=false;submissionState=null;workspaceView="information";renderWorkspace();});
    }));
    root.append(reload,renderSender(),sendingSettings());
    if(sessionOnly){const box=el("section",undefined,"detail");box.append(el("h2","Session only"),el("p","Session only: nothing is kept. This build is for synthetic records pending storage review."),button("Switch to an encrypted record",()=>changeView("convert")),button("End session",()=>changeView("end"),"danger"),sessionFaq());root.append(box);return;}
    root.append(renderDelete());return;
  }
  if(record.migration_required){root.append(renderUpgrade());return;}
  if(workspaceView==="information"||!record.profile){root.append(renderProfile());return;}
  if(workspaceView==="home"){root.append(renderHome());return;}
  if(workspaceView==="submissions"){root.append(renderSubmissions());return;}
  if(workspaceView==="coverage"){root.append(capabilityMatrix(workState.catalog,workState.workflow?.plan));const box=el("section",undefined,"detail");box.append(el("h2","What each broker asks for"));workState.catalog.forEach(r=>{const d=el("details",undefined,"history");d.append(el("summary",r.name+" · "+readiness(r)),requirementsGuide(r));box.append(d);});root.append(box);return;}
  root.append(renderBatch());
  const add = el("details", undefined, "start-here"); add.open = !workState.cases.length;
  const addBody = el("div", undefined, "drop-guidance"); addBody.append(createCaseForm());
  add.append(el("summary", "Add a broker to your requests"), addBody); root.append(add);
  if (!workState.cases.length) {root.append(el("p", "Build the batch from your saved information, or add a known listing below.", "notice")); return;}
  if (!workState.cases.some(c => c.id === selectedCase)) selectedCase = workState.cases[0].id;
  const workspace = el("div", undefined, "workspace"), queue = el("nav", undefined, "queue"); queue.setAttribute("aria-label", "Each request");
  queue.append(el("h2", "Each request"), el("p", sessionOnly ? "Your requests · this session only" : "Your requests · encrypted history"));
  for (const c of workState.cases) {
    const item = workState.catalog.find(r => r.id === c.broker);
    const b = button("", () => {selectedCase = c.id; renderWorkspace();}, "queue-item" + (c.id === selectedCase ? " selected" : ""));
    b.setAttribute("aria-pressed", String(c.id === selectedCase));
    b.append(el("strong", item.name), el("span", c.kind === "private_database" ? "Private database · possession unknown" : human(c.match)),
      c.execution_status ? statusPill(c.execution_status) : el("span", c.attempt ? human(c.attempt.state) : human(c.request_status), "pill"));
    if (c.review_on) b.append(el("span", (c.due ? "Review due: " : "Review on: ") + c.review_on));
    queue.append(b);
  }
  workspace.append(queue, caseDetail(workState.cases.find(c => c.id === selectedCase))); root.append(workspace);
}
function createCaseForm() {
  const form = el("form", undefined, "profile-form");
  const broker = choice("Broker", workState.catalog.map(r => [r.id, r.name + (r.readiness === "manual_preparation" ? " · request preparation" : r.readiness === "owner_email" ? " · automated simulation" : " · guidance and tracking")]));
  const url = field("Exact public listing URL (stored locally; never fetched)", "listing_url");
  const note = field("Why review this broker? For a listing, record what matches and what conflicts. Keep notes limited to yourself.", "note", "", "textarea"); note.input.required = true;
  const self = consent("I am an adult acting only for myself. This is not a family or client profile.");
  const info = el("p", undefined, "muted");
  function changed() {
    const r = workState.catalog.find(r => r.id === broker.input.value);
    url.label.hidden = r.kind !== "public_listing"; url.input.required = !url.label.hidden;
    info.textContent = r.limits + (r.listing_hosts.length ? " Listing hosts: " + r.listing_hosts.join(", ") : "");
  }
  broker.input.addEventListener("change", changed); changed();
  form.append(broker.label, info, url.label, note.label, self.label);
  submitForm(form, "Create local case", async current => {
    const result = await api("/api/cases/create", {broker:broker.input.value,listing_url:url.label.hidden ? "" : url.input.value,note:note.input.value,self_only:self.input.checked});
    if (current !== generation) return;
    const old = new Set(workState.cases.map(c => c.id)); selectedCase = result.cases.find(c => !old.has(c.id)).id;
    workState = result; renderWorkspace(); message.textContent = "Case created locally. No search or request was sent.";
  }); return form;
}
function caseDetail(c) {
  const r = workState.catalog.find(r => r.id === c.broker), box = el("section", undefined, "detail");
  const emailRoute = r.readiness === "owner_email";
  box.append(el("p", emailRoute ? "EMAIL REQUEST" : c.kind === "private_database" ? "PRIVATE DATABASE REQUEST" : "PUBLIC LISTING REVIEW", "eyebrow"), el("h2", r.name));
  if (c.listing_url) box.append(el("p", c.listing_url, "mono"));
  if (emailRoute) box.append(emailSummary(c));
  const stats = el("dl", undefined, "status-grid");
  const email = c.execution_status;
  for (const [label,value] of [["Match",human(c.match)],email ? ["Email",human(email)] : ["Request",human(c.request_status)],
    ["Submission",email ? (c.execution?.result ? human(c.execution.result.outcome) + " · " + c.execution.result.at : "Not sent") : c.attempt ? human(c.attempt.state) : "Not recorded"],["Broker response",human(c.broker_response)],
    ["Listing visibility",human(c.visibility) + (c.visibility_at ? " · " + c.visibility_at : "")],["Next local review",c.review_on || "Not set"]]) {
    const pair = el("div",undefined,"pair"); pair.append(el("dt",label),el("dd",value)); stats.append(pair);
  }
  if (!emailRoute) box.append(stats, el("p", "Outcomes are manually reported by you. A blocked, failed or ambiguous check means unknown. An absent listing is a dated observation, never permanent erasure.","muted"), el("p",c.next_step,"next-step"));
  const guidance = el("details",undefined,"history");
  guidance.append(el("summary","Broker requirements and route evidence"),requirementsGuide(r),el("p",r.limits));
  r.sources.forEach(url=>{const p = el("p"); p.append(link("Official source ↗",url)); guidance.append(p);});
  if (r.readiness === "guidance_only") guidance.append(el("p","The following link attaches no identity. Inspect it yourself before disclosure; this entry has no verified request payload."),link("Open broker guidance ↗",r.destination));
  box.append(guidance);
  if (c.match === "candidate_found") {
    const form = el("form",undefined,"profile-form"), decision = choice("Match decision",[["confirm","This is my listing"],["reject","This is not my listing"]]);
    const note = field("Evidence for this decision", "match-note", "", "textarea"); note.input.required = true;
    form.append(decision.label,note.label); submitForm(form,"Save match decision",current=>command(c,decision.input.value,{note:note.input.value},current)); box.append(form);
  }
  if (r.readiness === "owner_email") box.append(executionPanel(c, r));
  if (c.request) box.append(requestPreview(c));
  if (!c.attempt && ["confirmed","not_applicable"].includes(c.match) && r.readiness === "manual_preparation") {
    const details = el("details",undefined,"history"); details.open = !c.request;
    details.append(el("summary",c.request ? "Revise request · approval will reset" : "Prepare one removal request"),prepareForm(c,r)); box.append(details);
  }
  if (c.attempt && ["handoff_started","uncertain"].includes(c.attempt.state)) {
    const handoff = el("div",undefined,"notice");
    handoff.append(el("h3","Continue this handoff"),el("p","This link carries no profile values. Opening it does not submit a request. If you already submitted or cannot tell, reconcile the result below before taking any further action."),
      link("Open official form for this handoff ↗",c.request.snapshot.route.destination));
    box.append(handoff);
    box.append(resultForm(c,"outcome","What happened on the broker site?",[["uncertain","I cannot tell whether it was submitted"],["submitted","I submitted it and have evidence"],["not_disclosed","I did not enter or disclose any information"]],"Record handoff outcome"));
  }
  if (c.attempt && c.attempt.state === "submitted_user_reported") box.append(resultForm(c,"response","Record the broker's reply",REPLY_OPTIONS,"Record reply"));
  if (c.kind === "public_listing" && c.match === "confirmed") box.append(resultForm(c,"check","Your check of the exact listing",[["blocked","Check blocked · unknown"],["failed","Check failed · unknown"],["ambiguous","Ambiguous result · unknown"],["present","Listing observed present"],["absent","Listing observed absent"]],"Record dated observation"));
  const review = el("form",undefined,"profile-form"), when = field("Next local review date (no background reminder)","review-date",c.review_on || "","date");
  review.append(when.label); submitForm(review,"Save review date",current=>command(c,"review",{date:when.input.value},current)); box.append(review);
  const notes = el("details",undefined,"history"), noteForm = el("form",undefined,"profile-form"), note = field("Evidence note · no passwords, verification codes or document contents", "evidence-note", "", "textarea");
  note.input.required = true; noteForm.append(note.label); submitForm(noteForm,"Add evidence note",current=>command(c,"note",{note:note.input.value},current));
  notes.append(el("summary","Add a private evidence note"),noteForm); box.append(notes);
  const history = el("details",undefined,"history"), entries = el("ol"); history.open = true;
  history.append(el("summary","Dated history · " + c.history.length + " events"));
  [...c.history].reverse().forEach(event=>{const li = el("li"); li.append(el("strong",eventName(event.kind)),el("time",localTime(event.at)),el("p",event.note),el("span",SOURCES[event.provenance] || sentence(human(event.provenance || "")),"muted")); if(event.result) li.append(el("p","Observation: " + human(event.result))); entries.append(li);});
  history.append(entries); box.append(history); return box;
}
function senderBanner(s) {
  if (s.kind === "gmail") return s.configured ? "Sender: Gmail " + s.account + (s.simulated ? " (local fake Google)" : "") + ". This build sends only test messages to yourself; sending to brokers through Gmail is a later, separately approved pilot." : "Sender: Gmail, not connected. Connect it under Privacy & settings.";
  if (s.kind === "fake") return s.configured ? "Sender: local fake provider. Simulation only; nothing leaves this Mac." : "The local fake sender stopped responding. Restart the app.";
  return "No sender is configured in this session. You can prepare and approve, but nothing can be sent.";
}
async function senderCommand(action, data, current) {
  const result = await api("/api/sender", {action, data});
  if (current !== generation) return;
  if (result.locked) {wipe(); renderLocked(); message.textContent = "The vault locked during the test. Nothing else was sent."; return;}
  workState = result; renderWorkspace();
  const t = result.test_result;
  message.textContent = t ? "Test message: " + human(t.outcome) + (t.provider_message_id ? " · Gmail id " + t.provider_message_id : "") + ". Check your inbox." :
    action === "disconnect" ? (result.revoked ? "Disconnected; Google revoked Velum's access." : "Disconnected locally. Google did not confirm revocation; remove Velum under your Google Account's third-party access.") : "Saved.";
}
function renderSender() {
  const s = workState.sender || {}, box = el("section", undefined, "detail");
  box.append(el("h2", "Sending account"));
  if (s.kind !== "gmail") {
    box.append(el("p", s.kind === "fake" ? "This session sends approved emails to a local fake provider (simulation only)." : "This session was started without a sender. Start Velum with --sender gmail to connect your own Gmail account."));
    return box;
  }
  const g = s.gmail, flow = g.flow || {};
  box.append(el("p", (g.simulated ? "Simulation: this session talks to a local fake Google. " : "") + "Velum asks Google only for permission to send email as you (gmail.send) and for your verified address. It cannot read your mailbox. The grant is stored only in your encrypted vault.", "muted"));
  if (g.connected) {
    box.append(el("p", "Connected: " + g.account + " · since " + g.connected_at));
    if (g.last_test) box.append(el("p", "Last test: " + human(g.last_test.outcome) + " · " + human(g.last_test.reason) + " · " + g.last_test.at, "muted"));
    box.append(el("p", "This build sends only test messages to this address. Sending to brokers through Gmail is a later, separately approved pilot.", "notice"));
    const actions = el("div", undefined, "actions");
    actions.append(button("Send a test message to myself", () => { pendingSend = "test"; renderWorkspace(); }, "primary"), button("Disconnect and revoke", () => {
      if (!window.confirm("Remove this Gmail connection and ask Google to revoke Velum's access?")) return;
      run(current => senderCommand("disconnect", {}, current));
    }));
    box.append(actions);
    if (pendingSend === "test") {
      const confirm = el("section", undefined, "confirm-send"), go = el("div", undefined, "actions");
      confirm.setAttribute("role", "group"); confirm.setAttribute("aria-label", "Confirm the test message");
      go.append(button("Send the test message", () => run(current => { pendingSend = null; return senderCommand("test_send", {acknowledged: true}, current); }), "primary"),
        button("Cancel", () => { pendingSend = null; renderWorkspace(); }));
      confirm.append(el("h3", "Send a test message?"), el("p", "A short test email goes from " + g.account + " to " + g.account + ". No broker is contacted and no personal details are included."), go);
      box.append(confirm);
    }
    return box;
  }
  if (flow.state === "waiting" && pendingAuthorize) {
    box.append(el("p", "Next: open Google, choose your account and allow sending. Then return here and check the connection.", "notice"),
      link("Open Google sign-in ↗", pendingAuthorize),
      button("Check connection", () => run(async current => {const st = await api("/api/cases"); if (current !== generation) return; workState = st; renderWorkspace();})));
    return box;
  }
  if (flow.state === "failed") box.append(el("p", "The last connection attempt did not complete: " + human(flow.reason) + ".", "notice"));
  const steps = el("ol");
  ["In Google Cloud Console, create a project for yourself and enable the Gmail API.",
   "Under Google Auth Platform, set the audience to External, keep the publishing status at Testing, and add your own Gmail address as a test user. Testing-mode grants expire after 7 days; reconnect when that happens.",
   "Under Data access, add the scopes gmail.send, openid and email. Nothing broader is needed.",
   "Create an OAuth client of type Desktop app, and paste its Client ID and secret below. Velum keeps them only in your encrypted vault."].forEach(t => steps.append(el("li", t)));
  const form = el("form", undefined, "profile-form"), id = field("OAuth Client ID (Desktop app)", "gmail-client-id", "", "text", 200), clientSecret = secret("Client secret", "off", 8);
  form.append(id.label, clientSecret.label);
  submitForm(form, "Start Gmail connection", async current => {
    const result = await api("/api/sender", {action: "connect_start", data: {client_id: id.input.value, client_secret: clientSecret.input.value}});
    if (current !== generation) return;
    pendingAuthorize = result.authorize_url;
    const st = await api("/api/cases"); if (current !== generation) return;
    workState = st; renderWorkspace();
  });
  box.append(el("h3", "Connect your Gmail account"), steps, form);
  return box;
}
function executionPanel(c, r) {
  const job = c.execution, status = c.execution_status, sender = workState.sender || {}, box = el("section", undefined, "preview");
  box.append(el("h3", "Your email to " + (r.name || brokerName(c.broker))),
    el("p", senderBanner(sender), "notice"));
  if (["source_review_due", "jurisdiction_unsupported"].includes(status)) box.append(el("p", c.next_step, "notice"));
  if (job) {
    const m = job.message;
    box.append(emailTable(m, job.sender_account ? "From (your connected account)" : "From (you)"), el("pre", m.body),
      el("p", "Only this exact email can be sent. Any change to your information, the route’s official source or related requests needs a fresh review.", "muted"));
    if (job.result) box.append(el("p", emailStatus(status)[0] + " · " + localTime(job.result.at), "muted"));
    box.append(technicalDetails(job));
  }
  const contract = el("details", undefined, "history");
  contract.append(el("summary", "What this request does and does not prove"), el("p", r.limits), el("p", r.automation, "muted"));
  box.append(contract);
  if (["not_prepared", "prepared", "expired", "invalidated", "revoked", "not_sent", "user_reported_not_sent"].includes(status)) {
    const form = el("form", undefined, "profile-form"), overlap = workState.workflow.plan.find(p => p.broker === c.broker)?.drop_overlap;
    const ack = consent("I reviewed my recorded DROP request and want to prepare this separate request despite possible overlap.");
    const needs = (r.requirements?.inputs || []).map(i => i.label);
    form.append(el("p", (needs.length ? "Uses only these values from My information: " + needs.join("; ") + "." : "Uses only the saved values this route's contract lists.") + " Preparing sends nothing.", "muted"));
    if (overlap) form.append(ack.label);
    const prepareButton = submitForm(form, job ? "Prepare a fresh email" : "Prepare exact email", current => executionCommand(c, "prepare", {drop_acknowledged: ack.input.checked === true}, current));
    if (["prepared", "expired"].includes(status)) prepareButton.className = "secondary";  // Approval is the next step.
    box.append(form);
  }
  if (["prepared", "expired"].includes(status)) {
    const form = el("form"), ack = consent("I reviewed this exact sender, recipient, subject and body, and approve sending this one email, once.");
    if (sessionOnly()) form.append(el("p", "This session can’t see earlier ones. If you already asked this broker in a past session, this may be a duplicate request.", "notice"));
    form.append(ack.label); submitForm(form, "Approve this exact email", current => executionCommand(c, "approve", {fingerprint: job.fingerprint, acknowledged: ack.input.checked}, current));
    box.append(whyMyself(), el("p", "Shared with " + (r.name || brokerName(c.broker)) + ": " + sharedText(job) + ". Nothing else."), form);
  }
  if (status === "approved") {
    box.append(el("p", "Approval expires " + localTime(job.approval.expires_at) + ".", "muted"));
    const paused = workState.workflow?.paused && workState.workflow.case_ids.includes(c.id);
    if (paused) box.append(el("p", "Batch paused. Resume above before sending.", "notice"));
    const actions = el("div", undefined, "actions");
    if (sendMethod === "self") box.append(selfSendPanel(c, job, paused));
    else if (sendMethod === "velum") {
      const send = button("Send this email now", () => { pendingSend = c.id; renderWorkspace(); }, "primary");
      send.disabled = paused || !sender.broker_sending;
      actions.append(send);
      if (pendingSend === c.id && !send.disabled) box.append(sendConfirmation([c], () => run(current => {
        pendingSend = null; return executionCommand(c, "dispatch", {fingerprint: job.fingerprint}, current);
      })));
    } else actions.append(button("Choose how to send", () => changeView("send-choice"), "primary"));
    actions.append(button("Revoke approval", () => run(current => executionCommand(c, "revoke", {}, current))));
    box.append(actions);
  }
  if (status === "uncertain") {
    const form = el("form", undefined, "profile-form"), result = choice("What did you find?", [["sent_found", "I found it in my Sent folder"], ["broker_replied", "The broker replied to it"], ["not_found_in_sent", "I couldn't find it in my Sent folder"]]);
    const note = field("What you checked and when", "send-reconcile-note", "", "textarea"); note.input.required = true;
    form.append(el("p", "Velum never resends an uncertain email. Finding it or a broker reply confirms it was sent. Not finding it is recorded, but it stays uncertain: only a rejection from your mail provider proves it wasn't sent.", "muted"), result.label, note.label);
    submitForm(form, "Record what you found", current => executionCommand(c, "reconcile", {result: result.input.value, note: note.input.value}, current));
    box.append(form);
    const again = el("details", undefined, "history"), againForm = el("form", undefined, "profile-form");
    const risk = consent("I understand this new request may duplicate the earlier one, which may already have reached the broker.");
    againForm.append(el("p", "Only if you're sure it never arrived. The earlier email stays in your history as uncertain.", "muted"), risk.label);
    submitForm(againForm, "Prepare a new request anyway", current => executionCommand(c, "prepare", {drop_acknowledged: false, duplicate_acknowledged: risk.input.checked === true}, current));
    again.append(el("summary", "Prepare a new request anyway"), againForm); box.append(again);
  }
  if (["transport_accepted", "user_confirmed_sent", "user_sent"].includes(status)) box.append(resultForm(c, "response", "Record the broker's reply", REPLY_OPTIONS, "Record reply"));
  return box;
}
function mailto(m) {
  // The address is a reviewed, pinned recipient. Subject and body are encoded; lines end in CRLF.
  return "mailto:" + m.to + "?subject=" + encodeURIComponent(m.subject) + "&body=" + encodeURIComponent(m.body.replace(/\r?\n/g, "\r\n"));
}
function copyButton(label, value) {
  return button(label, () => {
    const clipboard = navigator.clipboard;
    if (!clipboard) { errorBox.textContent = "Copying isn’t available here. Select the text above and copy it instead."; errorBox.hidden = false; return; }
    placeBanners();
    clipboard.writeText(value).then(() => {message.textContent = label.replace("Copy ", "") + " copied.";},
      () => {errorBox.textContent = "Copying didn’t work. Select the text above and copy it instead."; errorBox.hidden = false;});
  });
}
function selfSendPanel(c, job, paused) {
  const m = job.message, box = el("div", undefined, "self-send");
  const open = el("a", "Open in my mail app", "external-primary"); open.href = mailto(m);
  open.addEventListener("click", () => { leavingForMail = Date.now(); });
  const copies = el("div", undefined, "actions");
  copies.append(copyButton("Copy address", m.to), copyButton("Copy subject", m.subject), copyButton("Copy body", m.body));
  const done = el("div", undefined, "actions");
  const sent = button("I sent it", () => run(current => executionCommand(c, "self_sent", {fingerprint: job.fingerprint, result: "sent"}, current)), "primary");
  const unsure = button("I’m not sure it went", () => run(current => executionCommand(c, "self_sent", {fingerprint: job.fingerprint, result: "unsure"}, current)));
  sent.disabled = unsure.disabled = Boolean(paused);
  done.append(sent, unsure);
  box.append(el("h4", "Send it yourself"),
    el("p", "Open it in your mail app, check it’s sent from " + m.from + ", and press Send there without changing anything. Then come back and tell Velum what happened."),
    open, el("p", "If your mail app doesn’t open, copy each part into a new email instead. Copied text stays on your clipboard until you copy something else.", "muted"),
    copies, done, el("p", "“I’m not sure it went” keeps it uncertain until you check your Sent folder, so Velum never helps you send a duplicate by accident.", "muted"));
  return box;
}
// Plain words for an email's state, with the design system's status tone.
const EMAIL_STATUS = {
  not_prepared: ["Not prepared yet", "review"], prepared: ["Ready for your review", "review"],
  expired: ["Approval expired · review again", "action"], approved: ["Approved, not sent", "review"],
  revoked: ["Approval withdrawn", "waiting"], invalidated: ["Something changed · prepare a fresh email", "action"],
  source_review_due: ["Paused · official source under review", "waiting"], jurisdiction_unsupported: ["Doesn’t apply where you live", "waiting"],
  dispatching: ["Sending", "waiting"], transport_accepted: ["Sent · your mail provider accepted it", "done"],
  user_sent: ["Sent · you sent it yourself", "done"], user_confirmed_sent: ["Sent · you confirmed it", "done"],
  uncertain: ["Not sure it was sent", "uncertain"], not_sent: ["Not sent · your mail provider refused it", "error"],
  user_reported_not_sent: ["Not sent · your report", "waiting"]};
function emailStatus(s) { return EMAIL_STATUS[s] || [human(s || "not_prepared"), "waiting"]; }
function statusPill(s) { const [words, tone] = emailStatus(s); return el("span", words, "pill tone-" + tone); }
// Stored times are UTC; people read them in their own time zone.
function localTime(value) {
  if (!value) return "";
  const day = /^\d{4}-\d{2}-\d{2}$/.test(value), d = new Date(day ? value + "T12:00:00" : value);
  if (isNaN(d.getTime())) return value;
  return day ? d.toLocaleDateString(undefined, {dateStyle: "medium"}) : d.toLocaleString(undefined, {dateStyle: "medium", timeStyle: "short"});
}
const SHARED = {full_name: "your name", first_name: "your first name", last_name: "your last name", email: "your email address", us_state: "your state of residence"};
function sharedText(job) {
  const order = Object.keys(SHARED), rank = k => order.includes(k) ? order.indexOf(k) : order.length;
  const names = Object.keys(job.fields || {}).sort((a, b) => rank(a) - rank(b)).map(k => SHARED[k] || human(k));
  return names.length > 1 ? names.slice(0, -1).join(", ") + " and " + names.at(-1) : names[0] || "nothing from My information";
}
function whyMyself() {
  const box = el("details", undefined, "history");
  box.append(el("summary", "Why does the email say I’m sending it myself?"),
    el("p", "Because you are. It’s your request about your own data, from your own email address, in words you approved. Velum is software on your Mac, like a mail app. It isn’t acting as your agent, and the broker never hears from Velum."),
    el("p", "That sentence matters. Privacy laws let brokers ask an agent (someone acting for another person) for signed permission and extra checks. Saying the request comes from you tells the broker no agent is involved."),
    el("p", "If you let Velum send it, nothing changes: it still goes from your account, only after you approve this exact text."));
  return box;
}
function technicalDetails(job) {
  const box = el("details", undefined, "history"), list = el("dl", undefined, "technical"), c = job.contract || {};
  const rows = [["Contract", job.contract_id + (job.contract_version ? " · revision " + job.contract_version : "")],
    ["Source checked", c.checked || ""], ["Fingerprint", job.fingerprint], ["Prepared (UTC)", job.prepared_at || ""],
    ["Approved (UTC)", job.approval?.at || ""], ["Approval expires (UTC)", job.approval?.expires_at || ""],
    ["Handed to sender (UTC)", job.dispatched_at || ""],
    ["Transport result", job.result ? job.result.outcome + " · " + job.result.reason + " · " + job.result.at : ""],
    ["Provider message id", job.result?.provider_message_id || ""]];
  rows.filter(([, v]) => v).forEach(([k, v]) => list.append(el("dt", k), el("dd", v, "fingerprint")));
  box.append(el("summary", "Technical details"), list);
  return box;
}
function emailTable(m, fromLabel = "From") {
  const table = el("table", undefined, "email-table");
  for (const [label, value] of [[fromLabel, m.from], ["To", m.to], ["Subject", m.subject]]) {
    const tr = el("tr"); tr.append(el("th", label), el("td", value)); table.append(tr);
  }
  return table;
}
function renderApprove() {
  const box = el("section", undefined, "detail"), cases = new Map(workState.cases.map(c => [c.id, c]));
  const order = (stepper ? stepper.order : []).filter(id => cases.get(id)?.execution);
  const live = id => ["prepared", "expired"].includes(cases.get(id).execution_status);
  const left = order.filter(id => !stepper.done[id] && live(id)), current = left[0];
  const approved = order.filter(id => stepper.done[id] === "approved").length;
  box.append(el("p", "Your requests · Review", "eyebrow"), el("h2", "Review your emails"),
    el("p", "Approve each email on its own. Approving doesn’t send anything; you choose how to send them once you’re done."));
  const layout = el("div", undefined, "stepper"), list = el("nav", undefined, "stepper-list"), panel = el("section", undefined, "stepper-panel");
  list.setAttribute("aria-label", "Emails to review");
  for (const id of order) {
    const c = cases.get(id), done = stepper.done[id];
    const [words, tone] = done === "approved" && c.execution_status === "approved" ? ["Approved, not sent", "done"] : done === "skipped" ? ["Skipped", "waiting"]
      : id === current ? ["Reviewing", "review"] : live(id) ? ["Next", "review"] : emailStatus(c.execution_status);
    const row = el("div", undefined, "stepper-item" + (id === current ? " current" : ""));
    if (id === current) row.setAttribute("aria-current", "step");
    row.append(el("strong", brokerName(c.broker)), el("span", words, "pill tone-" + tone)); list.append(row);
  }
  list.append(el("p", approved + " of " + order.length + " approved", "muted"));
  if (current) {
    const c = cases.get(current), job = c.execution, name = brokerName(c.broker);
    const heading = el("h3", name);
    panel.append(el("p", "Private database request · Email " + (order.indexOf(current) + 1) + " of " + order.length, "eyebrow"), heading);
    if (stepper.moved) focusSoon(heading);
    if (c.execution_status === "expired") panel.append(el("p", "Your earlier approval expired, so this needs approving again.", "notice"));
    panel.append(emailTable(job.message), el("pre", job.message.body), whyMyself(),
      el("p", "Shared with " + name + ": " + sharedText(job) + ". Nothing else."), technicalDetails(job));
    if (sessionOnly()) panel.append(el("p", "This session can’t see earlier ones. If you already asked " + name + " in a past session, this may be a duplicate request.", "notice"));
    const ack = consent("I approve this exact email to " + name + ". Any change to it needs a new approval."), actions = el("div", undefined, "actions");
    const approve = button(left.length === 1 ? "Approve and finish" : "Approve and next", () => run(async now => {
      await executionCommand(c, "approve", {fingerprint: job.fingerprint, acknowledged: ack.input.checked}, now);
      if (now !== generation || !stepper) return;
      stepper.done[c.id] = "approved"; stepper.moved = true; renderWorkspace();
    }), "primary");
    approve.disabled = true;
    ack.input.addEventListener("change", () => { approve.disabled = !ack.input.checked; });
    actions.append(approve, button("Skip for now", () => { stepper.done[c.id] = "skipped"; stepper.moved = true; renderWorkspace(); }));
    panel.append(ack.label, actions);
  } else {
    const ready = batchCases(c => c.execution_status === "approved").length, heading = el("h3", approved === 1 ? "1 email approved" : approved + " emails approved");
    if (stepper.moved) focusSoon(heading);
    panel.append(heading,
      el("p", ready ? "Nothing has been sent yet. Next, choose how these emails go out." : order.length ? "Nothing is approved, so nothing can be sent." : "There are no emails waiting for your review."));
    const actions = el("div", undefined, "actions");
    if (ready) actions.append(button(sendMethod ? "Go to sending" : "Choose how to send", () => changeView(sendMethod ? "queue" : "send-choice"), "primary"));
    if (order.some(id => stepper.done[id] === "skipped" && live(id))) actions.append(button("Review skipped emails", () => {
      order.forEach(id => { if (stepper.done[id] === "skipped") delete stepper.done[id]; }); renderWorkspace();
    }));
    actions.append(button("Back to your requests", () => changeView("queue")));
    panel.append(actions);
  }
  layout.append(list, panel); box.append(layout);
  return box;
}
function emailSummary(c) {
  // What an email case means in plain words; contract ids and fingerprints sit under Technical details.
  const job = c.execution, box = el("div"), stats = el("dl", undefined, "status-grid");
  const sentAt = job && (job.result?.at || job.dispatched_at);
  for (const [label, value] of [["Sent", sentAt && !["not_sent"].includes(c.execution_status) ? localTime(sentAt) : "Not sent"],
    ["Broker’s reply", c.broker_response && c.broker_response !== "unknown" ? human(c.broker_response) : "None recorded"],
    ["Prepared", job ? localTime(job.prepared_at) : "Not yet"],
    ["Approval", job?.dispatched_at ? "Used when sent" : job?.approval ? "Expires " + localTime(job.approval.expires_at) : job?.state === "prepared" ? "Not approved" : "Not needed now"],
    ["Next review", c.review_on ? localTime(c.review_on) : "Not set"]]) {
    const pair = el("div", undefined, "pair"); pair.append(el("dt", label), el("dd", value)); stats.append(pair);
  }
  box.append(statusPill(c.execution_status), stats, el("p", "A sent email is not the broker’s reply. Replies are what you record from your inbox; “says it deleted” is the broker’s own report.", "muted"), el("p", c.next_step, "next-step"));
  return box;
}
// The attention home: what needs you, what is ready, what is waiting and what was reported.
// Where Home's date came from, in plain words.
const HOME_SOURCES = {attempt: "Tried to send", sent: "Sent", prepared: "Prepared", "reply you recorded": "Reply recorded",
  "listing you added": "Listing added"};
function localDate(value) {
  // A local calendar day for a timestamp; a date someone entered is shown as that day.
  if (!value) return "";
  const day = /^\d{4}-\d{2}-\d{2}$/.test(value), d = new Date(day ? value + "T12:00:00" : value);
  return isNaN(d.getTime()) ? value : d.toLocaleDateString(undefined, {dateStyle: "medium"});
}
const GROUP_TITLES = {do: "You need to do", review: "Ready to review", waiting: "Waiting on the broker", recorded: "Outcome recorded"};
function brokerName(id) { return ((workState.catalog || []).find(r => r.id === id) || {}).name || id; }
function renderHome() {
  const home = workState.attention || {items: [], counts: {}}, counts = home.counts || {}, box = el("section", undefined, "home");
  const pending = counts.do || 0, quiet = !pending && !counts.review;
  const phrase = (n, one, many) => n + " " + (n === 1 ? one : many);
  box.append(el("h2", quiet ? "Nothing needs your attention" : pending ? (pending === 1 ? "One thing needs you" : pending + " things need you") : "Nothing needs you right now"));
  const summary = [counts.review ? phrase(counts.review, "request is ready to review", "requests are ready to review") : "",
    counts.waiting ? phrase(counts.waiting, "request is waiting on a broker", "requests are waiting on a broker") : "",
    counts.recorded ? phrase(counts.recorded, "outcome is recorded", "outcomes are recorded") : ""].filter(Boolean);
  box.append(el("p", summary.length ? summary.join(", ") + "." : "No requests yet. Build them under Your requests when you’re ready.", "lede"));
  if (quiet && counts.waiting) box.append(el("p", "When you record a broker’s reply, anything you need to do shows up here.", "muted"));
  for (const group of ["do", "review", "waiting", "recorded"]) {
    const items = home.items.filter(a => a.group === group);
    if (!items.length) continue;
    const section = el("section", undefined, "attention-group");
    section.append(el("h3", GROUP_TITLES[group]));
    for (const a of items) {
      const row = el("article", undefined, "attention-item"), head = el("div", undefined, "attention-head");
      head.append(el("strong", brokerName(a.broker)), el("span", a.label, "pill tone-" + a.tone));
      row.append(head, el("p", a.detail));
      if (a.date) row.append(el("p", (a.source === "date you chose" ? "Your review date: " + localDate(a.date) : (HOME_SOURCES[a.source] || "Since") + " " + localDate(a.date)), "muted"));
      if (a.check_on) row.append(el("p", "You’ll check again on " + localDate(a.check_on), "muted"));
      row.append(button(group === "do" ? "Open and act" : "Open", () => { selectedCase = a.case_id; changeView("queue"); }, group === "do" ? "primary" : "secondary"));
      section.append(row);
    }
    box.append(section);
  }
  box.append(calendarOffer(home.items.filter(a => a.group === "waiting" && a.check_on)));
  return box;
}
function icsText(value) { return String(value).replace(/[\\;,]/g, c => "\\" + c).replace(/\r?\n/g, "\\n"); }
function calendarFile(items, now = new Date()) {
  const stampText = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Velum//Check-in dates//EN", "CALSCALE:GREGORIAN"];
  for (const a of items) {
    const day = a.check_on.replaceAll("-", "");
    lines.push("BEGIN:VEVENT", "UID:" + a.case_id + "-" + day + "@velum.invalid", "DTSTAMP:" + stampText, "DTSTART;VALUE=DATE:" + day,
      "SUMMARY:" + icsText("Velum: check for a reply from " + brokerName(a.broker)), "END:VEVENT");
  }
  lines.push("END:VCALENDAR");
  return lines.join("\r\n") + "\r\n";
}
function calendarOffer(items) {
  const box = el("details", undefined, "history");
  box.append(el("summary", "Add check-in dates to my calendar"));
  if (!items.length) {
    box.append(el("p", "Choose a review date on a waiting request (open it from this page), and you can add it to your calendar here. Velum never sets dates for you or calls a broker late.", "muted"));
    return box;
  }
  const save = button("Save calendar file", () => {
    const url = URL.createObjectURL(new Blob([calendarFile(items)], {type: "text/calendar"}));
    const link = el("a"); link.href = url; link.download = "velum-check-ins.ics"; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    message.textContent = "Calendar file saved. Open it to add the dates; Velum doesn’t track it after that.";
  });
  box.append(el("p", "Your calendar can remind you while Velum is closed. This saves a file with " + items.length + " date" + (items.length === 1 ? "" : "s") + " and the brokers’ names to your Downloads folder. That file stays on your Mac" + (sessionOnly() ? ", even after this session ends." : ".") + " Nothing else is included."), save);
  return box;
}
function renderSendChoice() {
  const sender = workState.sender || {}, inSession = sessionOnly(), box = el("section", undefined, "detail");
  const approved = (workState.workflow?.items || []).filter(i => i.state === "email_approved").length;
  const pick = method => () => { sendMethod = method; changeView("queue"); };
  const card = (eyebrow, title, intro, rows, ...actions) => {
    const c = el("section", undefined, "send-option"), dl = el("dl");
    rows.forEach(([k, v]) => dl.append(el("dt", k), el("dd", v)));
    c.append(el("p", eyebrow, "eyebrow"), el("h3", title), el("p", intro), dl, ...actions); return c;
  };
  const grid = el("div", undefined, "send-options");
  grid.append(card("Nothing to connect", "Send them yourself", "Velum opens each approved email in your mail app, already filled in. You press Send there, then tell Velum “I sent it”.",
    [["What it needs", "The mail app on this Mac. If it doesn’t open, copy buttons fill in the email for you."],
     ["What Velum holds", "No email permission at all."],
     ["What is kept", inSession ? "Nothing. This session’s record of “I sent it” is erased when you end it." : "Your report that you sent it, in your encrypted record."]],
    button("Send them myself", pick("self"), "primary")));
  const velum = button("Let Velum send them", pick("velum"));
  velum.disabled = !sender.broker_sending;
  const unavailable = sender.broker_sending ? [] : [el("p", sender.kind === "gmail" ? "Not available yet: sending to brokers through a real mail provider waits for the reviewed pilot." : "Not available here: no sender is configured.", "muted")];
  grid.append(card(inSession ? "This session only" : "Uses your connected account", inSession ? "Velum sends them for you" : "Velum sends and keeps track",
    "You press one Send button and Velum sends each approved email from your account, exactly as approved.",
    [["What it needs", sender.kind === "gmail" ? "A send-only permission you approve on Google’s own screen. Velum can send mail with it but can’t read your inbox." : sender.simulated ? "Nothing more. In this build Velum sends to a local fake mail service; no real email leaves this Mac." : "A connected sending account."],
     ["What Velum holds", inSession ? "That permission, in memory only." : "That permission, encrypted in your record until you disconnect it or delete everything."],
     ["What is kept", inSession ? "Nothing. When you end the session, Velum asks Google to revoke the permission and erases it." : "Your information, the emails you sent and every reply you record."]],
    velum, ...unavailable));
  if (inSession) grid.append(card("Needs an encrypted record", "Velum sends and keeps track",
    "The same, kept in an encrypted record stored only on this Mac, so Velum can track replies and warn you about duplicates next time.",
    [["What it needs", "Switching this session to an encrypted record. Nothing needs entering again."],
     ["What Velum holds", "The permission, encrypted, until you disconnect it or delete everything."],
     ["What is kept", "Your information, the emails you sent and every reply you record."]],
    button("Switch to an encrypted record", () => changeView("convert"))));
  box.append(el("p", "Your requests · Send", "eyebrow"), el("h2", "How do you want to send these?"),
    el("p", (approved ? "You approved " + approved + " email" + (approved === 1 ? "" : "s") + ". " : "") + "Choose how they go out. You can change this in Privacy & settings."),
    grid, el("p", "Whichever you choose, each email comes from you, not from Velum: from your address, exactly as you approved it, to the privacy address the broker publishes. If a send is uncertain, Velum never tries again on its own.", "notice"));
  return box;
}
function sendingSettings() {
  const box = el("section", undefined, "detail");
  box.append(el("h2", "Sending"), el("p", sendMethod === "self" ? "You send approved emails yourself from your mail app." : sendMethod === "velum" ? "Velum sends approved emails from your account." : "You haven’t chosen how approved emails go out yet."),
    button(sendMethod ? "Change how emails are sent" : "Choose how emails are sent", () => { sendMethod = null; changeView("send-choice"); }));
  return box;
}
function prepareForm(c,r) {
  const form=el("form",undefined,"profile-form"), flow=workState.workflow;
  form.append(el("p","Use the minimum fields required by this local draft from My information. Broker acceptance is untested; stop if the broker requires additional fields. A preferred current identifier, or the sole current identifier, is selected. Optional fields and former identifiers are not copied. Review every selected value on the next screen."));
  const overlap=flow.plan.find(p=>p.broker===c.broker)?.drop_overlap;
  const ack=consent("I reviewed my recorded DROP request and want to prepare a separate broker request despite possible overlap.");
  if(overlap)form.append(ack.label);
  const b=submitForm(form,"Prepare from saved information",current=>flowCommand("prepare",{id:c.id,case_version:c.version,drop_acknowledged:ack.input.checked===true},current));
  if(!flow.case_ids.includes(c.id)){b.disabled=true;form.append(el("p","Build or refresh the batch above to include this case."));}
  if(!r.source_fresh){b.disabled=true;form.append(el("p","The official source needs review before preparation."));}
  form.append(button("Edit shared information",()=>changeView("information")));return form;
}
function requestPreview(c) {
  const req = c.request, snap = req.snapshot, box = el("section",undefined,"preview"), r = snap.route;
  box.append(el("h3","Exact request disclosure"),el("p",snap.purpose),el("p","Destination: " + r.destination,"mono"),el("p","Method: you enter and submit the form yourself. This approval enables one manual handoff; it never enables automatic transmission."));
  if(snap.drop_overlap_acknowledged)box.append(el("p","You acknowledged possible overlap with a recorded DROP request. This separate request still requires its own exact approval.","notice"));
  const table = el("table"), head = el("tr"); head.append(el("th","Field"),el("th","Value you intend to disclose")); table.append(head);
  for(const [key,value] of Object.entries(snap.fields)) {const tr = el("tr"); tr.append(el("td",human(key)),el("td",value)); table.append(tr);} box.append(table);
  box.append(el("p",r.disclosure_notice),el("p","If fields, values or the destination change, stop and prepare a new preview before entering anything else. Website verification happens under that site's own review; do not store challenges here."),el("p","Profile revision " + snap.profile_version + " · route revision " + r.version + " · checked " + r.checked,"muted"),el("p","Request fingerprint: " + req.fingerprint,"fingerprint"));
  const steps = el("ol"); r.steps.forEach(s=>steps.append(el("li",s))); box.append(steps);
  if (["prepared","expired"].includes(c.request_status)) {
    const form = el("form"), ack = consent("I reviewed this destination, purpose, exact values and external-site disclosure. I approve one manual handoff for this request only.");
    form.append(ack.label); submitForm(form,"Approve this request",current=>command(c,"approve",{fingerprint:req.fingerprint,acknowledged:ack.input.checked},current)); box.append(form);
  }
  if (c.request_status === "approved") {
    box.append(el("p","Approval expires: " + req.approval.expires_at,"muted"));
    if(workState.workflow?.paused&&workState.workflow.case_ids.includes(c.id))box.append(el("p","Batch paused. Resume above before beginning a handoff. Already opened external pages are unaffected.","notice"));
    const actions = el("div",undefined,"actions");
    actions.append(button("Dry-run approval check",()=>run(current=>command(c,"handoff",{fingerprint:req.fingerprint,dry_run:true},current))),
      button("Begin manual handoff",()=>run(current=>command(c,"handoff",{fingerprint:req.fingerprint,dry_run:false},current)),"primary"),
      button("Revoke approval",()=>run(current=>command(c,"revoke",{},current)))); box.append(actions);
  } else if (!["prepared","expired","consumed"].includes(c.request_status)) box.append(el("p","This request is " + human(c.request_status) + ". Prepare a new preview before a handoff.","notice"));
  return box;
}
// One reply record for email and manual requests. Each is the broker's own report.
const REPLY_OPTIONS = [["acknowledged","Acknowledged the request"],["verification_required","Asked me to verify"],["verification_completed","I completed the verification"],["deletion_reported","Says it deleted my data"],["suppression_reported","Says it suppressed my data"],["no_record_reported","Says it holds no record of me"],["denied","Refused the request"],["unknown","Unclear or no usable reply"]];
function resultForm(c,action,title,options,submit) {
  const details = el("details",undefined,"history"), form = el("form",undefined,"profile-form"), result = choice(title,options), note = field("Evidence: what you saw and where. Use a short receipt excerpt, not verification links, passwords or identity documents.","result-note","","textarea");
  const received = action === "response" ? field("Reply received on · optional","reply-received","","date",10) : null;
  note.input.required = true;
  details.open = action === "outcome"; details.append(el("summary",title)); form.append(result.label);
  if (received) form.append(received.label);
  form.append(note.label);
  if (action === "outcome") form.append(el("p","Choose 'not disclosed' only if nothing was entered or sent, including while typing. It closes this handoff and revokes approval. An uncertain result stays blocked against another attempt.","muted"));
  submitForm(form,submit,current=>command(c,action,{result:result.input.value,note:note.input.value,...(received&&received.input.value?{received_on:received.input.value}:{})},current)); details.append(form); return details;
}
function activity() {
  if (session && Date.now() - lastTouch > 60000) {
    lastTouch = Date.now(); api("/api/touch", {}).catch(() => {wipe(); showUnavailable();});
  }
}
document.addEventListener("input", activity);
document.addEventListener("click", activity);
// Switching tabs, opening a broker page or checking email never ends a session.
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && bootstrap) refresh().catch(() => {wipe(); showUnavailable();});
});
window.addEventListener("beforeunload", event => {
  if (Date.now() - leavingForMail < 3000) return;  // Opening the mail app is not leaving Velum.
  if (session && (identityDirty || (status && status.store === "session"))) { event.preventDefault(); event.returnValue = ""; }
});
// Closing or reloading the page ends a session without saving and locks an encrypted record.
window.addEventListener("pagehide", () => {
  if (!session) return;
  const token = session, path = status && status.store === "session" ? "/api/end" : "/api/lock";
  wipe();
  fetch(path, {method:"POST", keepalive:true, headers:{"X-App-Token":bootstrap,"X-Private-Session":token,"Content-Type":"application/json"}, body:"{}"}).catch(() => {});
});
if (!bootstrap) {
  setRoot(el("p", "Open the private link printed in the Terminal window that started this app. For safety the link is removed from the address bar once the page loads, so after a reload or a bookmark, paste that terminal link again.", "notice"));
  document.querySelector("#broker-requirements").replaceChildren(el("p", "Open the terminal link to load the requirements guide."));
} else {
  setInterval(() => {if (!busy) refresh().catch(() => {wipe(); showUnavailable();});}, 2000);
  refresh().then(() => {if (!root.children.length) renderLocked();}).catch(() => {wipe(); showUnavailable();});
  loadRequirements();
}
