"use strict";
const token = document.querySelector('meta[name="demo-token"]').content;
const root = document.querySelector("#app");
const errorBox = document.querySelector("#error");
let state;
let selected;
let busy = false;

// Broker text is always a text node. No innerHTML, eval or executable templates.
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function button(label, handler, style = "secondary") {
  const b = el("button", label, style);
  b.type = "button";
  b.disabled = busy;
  b.addEventListener("click", handler);
  return b;
}
function date(value) { return new Date(value).toLocaleString(); }
function human(value) { return value.replaceAll("_", " "); }
function pair(label, value) {
  const box = el("div", undefined, "pair");
  box.append(el("dt", label), el("dd", value));
  return box;
}
async function fetchState() {
  const r = await fetch("/api/state", { headers: { "X-Demo-Token": token }, cache: "no-store" });
  if (!r.ok) throw new Error("Cannot read the local demo. Reload this page.");
  state = await r.json();
}
async function act(action, candidate, value, fingerprint) {
  if (busy) return;
  busy = true;
  errorBox.hidden = true;
  render();
  try {
    const body = { action, expected_version: state.version };
    if (candidate) body.candidate_id = candidate;
    if (value) body.value = value;
    if (fingerprint) body.fingerprint = fingerprint;
    const response = await fetch("/api/action", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Demo-Token": token }, body: JSON.stringify(body)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Action failed");
    state = result;
  } catch (error) {
    errorBox.textContent = `${error.message}. State refreshed where possible; no automatic action retry.`;
    errorBox.hidden = false;
    try { await fetchState(); } catch (_) { /* Original error stays visible. */ }
  } finally { busy = false; render(); }
}
function controlsFor(c) {
  const wrap = el("div", undefined, "actions");
  const run = (action, value, fingerprint) => () => act(action, c.id, value, fingerprint);
  if (!c.attempt_count) {
    if (c.decision === "pending") {
      wrap.append(button("Confirm this match", run("decide", "confirmed"), "primary"), button("Reject match", run("decide", "rejected")));
    } else if (c.decision === "rejected") {
      wrap.append(button("Reopen review", run("decide", "pending")));
    } else {
      if (!c.request) wrap.append(button("Prepare request preview", run("prepare", "standard"), "primary"));
      wrap.append(button("Reopen match review", run("decide", "pending")));
    }
  }
  return wrap;
}
function preview(c) {
  const r = c.request;
  const s = r.snapshot;
  const box = el("section", undefined, "preview");
  box.append(el("p", `REQUEST ${r.revision} · ${human(r.status).toUpperCase()}`, "eyebrow"), el("h3", "Review the exact disclosure"));
  const facts = el("dl");
  facts.append(pair("Mock destination", s.destination), pair("Destination check", s.destination_evidence), pair("Method", s.method), pair("Purpose", s.purpose));
  box.append(facts, el("p", "Exact fields in this simulated request", "strong"));
  const table = el("table");
  const tbody = el("tbody");
  for (const [key, value] of Object.entries(s.fields)) {
    const row = el("tr"); row.append(el("th", human(key)), el("td", value)); tbody.append(row);
  }
  table.append(tbody);
  box.append(table, el("p", s.disclosure, "muted"));
  const research = el("details");
  research.append(el("summary", `Official documentation · checked ${s.research_checked_on}`), el("p", s.research_status));
  const b = state.brokers[c.broker];
  research.append(el("p", b.required_information), el("p", b.method), el("p", b.limitation), el("p", `Reference (not contacted by the demo): ${s.official_reference}`, "mono"));
  box.append(research, el("p", `Approval fingerprint: ${r.fingerprint}`, "fingerprint"));
  if (!c.attempt_count) {
    const actions = el("div", undefined, "actions");
    if (r.status === "prepared") {
      const label = el("label", undefined, "consent");
      const check = el("input"); check.type = "checkbox";
      check.disabled = busy;
      label.append(check, document.createTextNode(" I reviewed this destination, method, purpose and every disclosed field. Approve this simulation only."));
      const approve = button("Approve this exact request", () => act("approve", c.id, undefined, r.fingerprint), "primary");
      approve.disabled = true;
      check.addEventListener("change", () => { approve.disabled = !check.checked || busy; });
      box.append(label); actions.append(approve);
    } else if (r.status === "approved") {
      actions.append(button("Simulate submission", () => act("submit", c.id, "accepted", r.fingerprint), "primary"));
      if (c.broker !== "acxiom") actions.append(button("Simulate uncertain result", () => act("submit", c.id, "uncertain", r.fingerprint)));
      actions.append(button("Use manual fallback", () => act("submit", c.id, "manual", r.fingerprint)));
    }
    box.append(actions);
    const revise = el("details");
    revise.append(el("summary", "Try an approval invalidation scenario"), el("p", "Either change creates a fresh preview and clears approval. Values remain fictional."));
    const revisions = el("div", undefined, "actions");
    revisions.append(button("Change mock email", () => act("prepare", c.id, "alternate_email")), button("Change mock destination", () => act("prepare", c.id, "alternate_destination")));
    revise.append(revisions); box.append(revise);
  }
  return box;
}
function followup(c) {
  const box = el("section", undefined, "followup");
  box.append(el("h3", "Response & follow-up"));
  if (c.verification === "pending") {
    box.append(el("p", "In a live workflow, you would handle verification on the broker's site or in your own inbox. This demo never asks for codes, passwords or identity documents."), button("Simulate verification handoff completed", () => act("verify", c.id), "primary"));
  }
  if (c.verification === "completed" && c.response === "none") {
    const actions = el("div", undefined, "actions");
    actions.append(button("Simulate broker reports deletion", () => act("response", c.id, "broker_reports_deletion")), button("Simulate refusal", () => act("response", c.id, "declined"))); box.append(actions);
  }
  const controls = el("div", undefined, "actions");
  const label = el("label", "Mock visibility check: ");
  const select = el("select");
  select.setAttribute("aria-label", "Mock visibility check outcome");
  for (const value of ["blocked", "absent", "present", "failed", "ambiguous"]) {
    const option = el("option", human(value)); option.value = value; select.append(option);
  }
  label.append(select);
  controls.append(label, button("Record mock check", () => act("check", c.id, select.value)));
  box.append(controls, el("p", "Each check is dated and scoped to one fictional record. Failed, blocked and ambiguous checks mean unknown.", "muted"));
  return box;
}
function detail(c) {
  const pane = el("article", undefined, "detail");
  pane.append(el("p", c.kind.toUpperCase(), "eyebrow"), el("h2", c.title), el("p", c.assessment));
  const table = el("table", undefined, "evidence");
  const head = el("tr");
  for (const label of ["Evidence", "Fictional profile", "Candidate", "Comparison"]) head.append(el("th", label));
  const thead = el("thead"); thead.append(head); table.append(thead);
  const body = el("tbody");
  for (const e of c.evidence) {
    const row = el("tr"); for (const key of ["field", "profile", "listing", "comparison"]) row.append(el("td", e[key])); body.append(row);
  }
  table.append(body);
  const scroller = el("div", undefined, "table-scroll"); scroller.append(table); pane.append(scroller);
  pane.append(el("p", `Fixture loaded ${date(c.found_at)} · ${c.listing_url}`, "muted mono"), controlsFor(c));
  const statuses = el("dl", undefined, "status-grid");
  statuses.append(pair("Match", human(c.decision)), pair("Request", c.request ? human(c.request.status) : "not prepared"), pair("Verification handoff", human(c.verification)), pair("Broker response", human(c.response)), pair("Latest visibility", c.current_visibility.toUpperCase()), pair("Check date", c.latest_check_at ? date(c.latest_check_at) : "not checked"));
  pane.append(statuses);
  if (c.request) pane.append(preview(c));
  if (c.attempt_count) pane.append(followup(c));
  const next = el("aside", undefined, "next-step"); next.append(el("strong", "Next useful step"), el("p", c.next_step)); pane.append(next);
  const history = el("details", undefined, "history");
  history.open = true;
  history.append(el("summary", "Dated status history · all events synthetic"));
  const list = el("ol");
  for (const e of state.events.filter(e => e.candidate_id === c.id).reverse()) {
    const item = el("li"); item.append(el("strong", human(e.kind)), el("time", date(e.at), "muted"));
    if (typeof e.detail === "string") item.append(el("p", e.detail));
    else { const d = el("details"); d.append(el("summary", "Inspect evidence"), el("pre", JSON.stringify(e.detail, null, 2))); item.append(d); }
    list.append(item);
  }
  history.append(list); pane.append(history);
  return pane;
}
function render() {
  root.replaceChildren();
  if (!state.loaded) {
    const box = el("section", undefined, "empty");
    box.append(el("p", "01 / START WITH A FICTIONAL IDENTITY", "eyebrow"), el("h2", "Meet Avery Example."), el("p", "One fictional adult. Four authored records. Explore a straightforward match, an ambiguous result, an uncertain submission and a manual handoff."), button("Load fictional sample", () => act("load_demo"), "primary"));
    root.append(box); return;
  }
  const profile = el("section", undefined, "profile");
  profile.append(el("div", `${state.identity.name} · age ${state.identity.age} · ${state.identity.city}, ${state.identity.region}`, "strong"), el("p", state.identity.notice, "muted")); root.append(profile);
  const stats = el("div", undefined, "stats");
  for (const [label, n] of [["authored candidates", state.candidates.length], ["awaiting match review", state.candidates.filter(c => c.decision === "pending").length], ["mock attempts", state.candidates.filter(c => c.attempt_count).length], ["live requests", 0]]) {
    const item = el("div"); item.append(el("strong", String(n)), el("span", label)); stats.append(item);
  }
  root.append(stats);
  selected = selected || state.candidates[0].id;
  const layout = el("div", undefined, "workspace");
  const queue = el("nav", undefined, "queue"); queue.setAttribute("aria-label", "Candidate review queue");
  queue.append(el("h2", "Review queue"), el("p", "Select a record to inspect.", "muted"));
  for (const c of state.candidates) {
    const b = button("", () => { selected = c.id; render(); }, "queue-item" + (selected === c.id ? " selected" : ""));
    b.setAttribute("aria-pressed", String(selected === c.id));
    b.append(el("strong", state.brokers[c.broker].name), el("span", c.title), el("span", human(c.decision), "pill")); queue.append(b);
  }
  layout.append(queue, detail(state.candidates.find(c => c.id === selected))); root.append(layout);
}
fetchState().then(render).catch(error => { root.textContent = error.message; });
