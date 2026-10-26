"use strict";
// Exercise shipped handlers with a minimal DOM. This is not native-browser QA.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function node(tag = "div") {
  // Parent links, after/before, closest and a button query let banner placement be exercised.
  const adopt = (parent, items) => items.forEach(i => { if (i && typeof i === "object") { if (i.parent && i.parent !== parent) i.parent.children = i.parent.children.filter(c => c !== i); i.parent = parent; } });
  return {tag, children: [], textContent: "", value: "", listeners: {}, attributes: {}, parent: null,
    append(...items) {adopt(this, items); this.children.push(...items);},
    replaceChildren(...items) {adopt(this, items); this.children = items;},
    addEventListener(event, handler) {this.listeners[event] = handler;},
    setAttribute(name, value) {this.attributes[name] = value;},
    after(...items) { const p = this.parent; if (!p) return; adopt(p, items); p.children = p.children.filter(c => !items.includes(c)); p.children.splice(p.children.indexOf(this) + 1, 0, ...items); },
    before(...items) { const p = this.parent; if (!p) return; adopt(p, items); p.children = p.children.filter(c => !items.includes(c)); p.children.splice(p.children.indexOf(this), 0, ...items); },
    closest(selector) { for (let n = this; n; n = n.parent) if (selector.split(",").some(sel => { sel = sel.trim(); return sel.startsWith(".") ? (n.className || "").split(" ").includes(sel.slice(1)) : n.tag === sel; })) return n; return null; },
    querySelectorAll(selector) { const all = n => (n.children || []).flatMap(c => [c, ...all(c)]); return selector === "button" ? all(this).filter(n => n.tag === "button") : []; }
  };
}
function page() {
  const elements = Object.fromEntries(["#private-app", "#private-error", "#private-message", "#broker-requirements", "#private-idle", "#app-header", "#before-start", "#drop-guide", "#user-guide", "#requirements-panel"].map(id => [id, node()]));
  const context = vm.createContext({
    crypto: require("node:crypto").webcrypto,
    document: {hidden: false, querySelector: id => elements[id], createElement: node,
      createTextNode: text => ({textContent: text}), addEventListener() {}},
    window: {addEventListener() {}}, location: {hash: "", pathname: "/"},
    history: {replaceState() {}}, setInterval() {},
    fetch() {throw new Error("Unexpected network request in synthetic UI test");}
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../privacy_cleanup/static/private.js"), "utf8"), context);
  return {elements, run: code => vm.runInContext(code, context)};
}
function descendants(item) {return [item, ...(item.children || []).flatMap(descendants)];}

test("legacy setup is reachable without entering a nonexistent passphrase", () => {
  const ui = page();
  ui.run("status = {store: 'vault', vault_exists: true, initialized: true, deletion_pending: false, locked: true}; renderLocked();");
  const find = text => descendants(ui.elements["#private-app"]).find(item => item.textContent === text);
  find("Set first passphrase for an older vault").listeners.click();
  assert.ok(find("Protect this vault with a passphrase"));
  const secrets = descendants(ui.elements["#private-app"]).filter(item => item.type === "password");
  assert.equal(secrets.length, 2);
  assert.ok(secrets.every(item => item.autocomplete === "new-password" && item.minLength === 12));
  find("Back to unlock").listeners.click();
  assert.ok(find("Unlock vault"));
  const unlock = descendants(ui.elements["#private-app"]).find(item => item.type === "password");
  assert.equal(unlock.minLength, 1, "Previously accepted normalized secrets must reach the server");
});

test("ordinary unlock keeps incomplete key cleanup visible until lock", async () => {
  const ui = page();
  ui.run("api = async () => ({cases: [], catalog: []});");
  await ui.run("acceptUnlock({session: 'synthetic-session', profile: null, notice: 'Synthetic key cleanup incomplete'}, generation)");
  const warnings = () => descendants(ui.elements["#private-app"]).filter(item => item.attributes?.role === "alert");
  assert.equal(warnings()[0].textContent, "Synthetic key cleanup incomplete");
  ui.run("record = {profile: null}; renderWorkspace();");
  assert.equal(warnings().length, 1, "Reloading profile data must not hide the warning");
  ui.run("wipe();");
  assert.equal(warnings().length, 0);
  await ui.run("acceptUnlock({session: 'synthetic-new-session', profile: null}, generation)");
  assert.equal(warnings().length, 0, "A successful cleanup must not retain a stale warning");
});

test("history materializes exact values only while a revision is open and clears on lock", () => {
  const ui=page();
  ui.run(`workState={catalog:[{id:'epsilon',name:'Epsilon'}]};
    submissionState={histories:{},entries:[{broker:'epsilon',revision:1,current:true,next_step:'Review this request.',request_status:'prepared',attempts:[],broker_response:'unknown',visibility:'not_applicable',
      request:{prepared_at:'2026-10-07T12:00:00Z',snapshot:{purpose:'Synthetic deletion',route:{destination:'https://example.invalid',method:'manual_web_form'},fields:{email:'history-canary@example.invalid'},identifiers:{email:'synthetic-reference'},profile_version:1}}}]};
    root.append(renderSubmissions());`);
  const text=()=>descendants(ui.elements['#private-app']).map(n=>n.textContent).join(' ');
  assert.ok(!text().includes('history-canary'));
  const details=descendants(ui.elements['#private-app']).find(n=>n.tag==='details');
  details.open=true;details.listeners.toggle();
  assert.ok(text().includes('history-canary@example.invalid'));
  assert.ok(text().includes('Values shown'));
  assert.ok(text().includes('Email address'), 'Field names are friendly');
  assert.ok(text().includes('Review this request.'));
  assert.ok(!text().includes('synthetic-reference'),'Internal identifiers are not product copy');
  details.open=false;details.listeners.toggle();
  assert.ok(!text().includes('history-canary'));
  details.open=true;details.listeners.toggle();
  ui.run('wipe();');
  assert.ok(!text().includes('history-canary'));
  assert.equal(ui.run('submissionState'),null);
});

test("late history response after lock cannot restore decrypted state", async () => {
  const ui=page();
  ui.run(`session='synthetic';status={initialized:true,locked:true};
    let releaseHistory; const pendingHistory=new Promise(resolve=>releaseHistory=resolve);
    api=async path=>path==='/api/submissions'?pendingHistory:{initialized:true,locked:true};
    changeView('submissions'); wipe();
    releaseHistory({entries:[{private:'late-canary'}]});`);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.run('submissionState'),null);
  assert.equal(ui.run('session'),null);
});

test("late migration case read after lock cannot restore profile or cases", async () => {
  const ui=page();
  ui.run(`record={version:1}; session='synthetic';
    let releaseCases; const pendingCases=new Promise(resolve=>releaseCases=resolve);
    api=async path=>path==='/api/upgrade'?{version:2,profile:{private:'synthetic'}}:pendingCases;
    run=work=>work(generation);root.append(renderUpgrade());`);
  const upgrade=descendants(ui.elements['#private-app']).find(n=>n.textContent==='Upgrade synthetic records');
  const pending=upgrade.listeners.click();
  await Promise.resolve();
  ui.run(`wipe();releaseCases({cases:[{private:'late-canary'}]});`);
  await pending;
  assert.equal(ui.run('record'),null);
  assert.equal(ui.run('workState'),null);
});

test("late workflow response after lock cannot restore batch or external evidence", async () => {
  const ui=page();
  ui.run(`workState={workflow:{version:0}};record={version:1};session='synthetic';
    let resolveWorkflow;api=()=>new Promise(resolve=>resolveWorkflow=resolve);
    const pendingWorkflow=flowCommand('plan',{},generation);wipe();
    resolveWorkflow({workflow:{external:[{note:'external-canary'}]}});`);
  await ui.run('pendingWorkflow');
  assert.equal(ui.run('workState'),null);
  assert.equal(ui.run('submissionState'),null);
});

test("external request evidence stays hidden until opened and disappears on lock", () => {
  const ui=page();
  ui.run(`workState={workflow:{external_brokers:[{id:'drop',name:'California DROP'}],external:[{id:'sample',broker:'drop',purpose:'Synthetic request',date:'2026-10-06',date_precision:'approximate',state:'submitted',history:[{at:'2026-10-07',state:'submitted',note:'ExternalCanary private evidence'}]}]}};
    submissionState={entries:[],emails:[],histories:{}};root.append(renderSubmissions());`);
  const text=()=>descendants(ui.elements['#private-app']).map(n=>n.textContent).join(' ');
  assert.ok(!text().includes('ExternalCanary'));
  assert.ok(text().includes('Made elsewhere') && text().includes('Submitted · your report'));
  const details=descendants(ui.elements['#private-app']).find(n=>n.tag==='details'&&/timeline-row/.test(n.className));
  details.open=true;details.listeners.toggle();
  assert.ok(text().includes('ExternalCanary'));
  assert.ok(text().includes('not a verified receipt'));
  details.open=false;details.listeners.toggle();
  assert.ok(!text().includes('ExternalCanary'));
  ui.run('wipe()');assert.equal(ui.run('workState'),null);
});

test("California DROP option is separate from other-state broker availability", () => {
  const ui=page();
  ui.run(`workState={workflow:{drop:{state:'eligible_self_reported',url:'https://privacy.ca.gov/drop/'},case_ids:[],counts:{},items:[],plan:[]}};root.append(renderBatch());`);
  const text=()=>descendants(ui.elements['#private-app']).map(n=>n.textContent).join(' ');
  assert.ok(text().includes('Start with California DROP'));
  ui.run(`workState.workflow.drop.state='not_eligible';root.replaceChildren(renderBatch());`);
  assert.ok(!text().includes('Start with California DROP'));
  assert.ok(text().includes('other broker routes remain available'));
});

test("owner-email panel shows the exact message as inert text and gates sending", () => {
  const ui = page();
  const panel = (paused, sender = '{kind: "fake", configured: true, simulated: true, broker_sending: true}') => ui.run(`sendMethod = "velum"; workState = {sender: ${sender}, workflow: {plan: [], paused: ${paused}, case_ids: ["c1"]}};
    executionPanel({id: "c1", version: 1, broker: "apollo", execution_status: "approved", next_step: "x",
      execution: {message: {from: "owner@example.invalid", to: "privacy@broker.invalid", subject: "Subject",
        body: "<script>alert(1)</script>"}, contract_id: "synthetic-v1", fingerprint: "f", approval: {expires_at: "t"}, result: null}},
      {limits: "l", automation: "a"})`);
  const all = descendants(panel(false));
  const body = all.find(item => item.textContent === "<script>alert(1)</script>");
  assert.equal(body.tag, "pre");
  assert.equal(all.filter(item => item.tag === "script").length, 0);
  const send = all.find(item => item.textContent === "Send this email now");
  assert.equal(send.disabled, false);
  const pausedSend = descendants(panel(true)).find(item => item.textContent === "Send this email now");
  assert.equal(pausedSend.disabled, true);
  const gmail = '{kind: "gmail", configured: true, simulated: false, broker_sending: false, account: "owner@example.invalid"}';
  const gmailSend = descendants(panel(false, gmail)).find(item => item.textContent === "Send this email now");
  assert.equal(gmailSend.disabled, true, "Real-provider broker sending stays disabled in this build");
});

test("capability matrix labels simulation honestly and explains a stale route", () => {
  const ui = page();
  const all = descendants(ui.run(`capabilityMatrix([
      {id: "cognism", name: "Cognism", capability: "automated_simulation", method: "owner_email", purpose: "Delete synthetic data", checked: "2026-10-08",
       freshness: {fresh: true, checked: "2026-10-08", review_by: "2026-11-07", reason: null}},
      {id: "lusha", name: "Lusha", capability: "automated_simulation", method: "owner_email", purpose: "Erase synthetic data", checked: "2026-09-01",
       freshness: {fresh: false, checked: "2026-09-01", review_by: "2026-10-01", reason: "Synthetic stale reason for this route only."}}],
    [{broker: "hunter", name: "Hunter", state: "research_only"}, {broker: "cognism", name: "Cognism", state: "ready_to_prepare_email"}])`));
  const text = all.map(n => n.textContent).join(" ");
  assert.ok(text.includes("Automated simulation"));
  assert.ok(text.includes("no real broker request has been sent"));
  assert.ok(text.includes("2026-11-07"));
  assert.ok(text.includes("Synthetic stale reason for this route only."));
  assert.equal(all.filter(n => n.textContent === "Hunter").length, 1);
  assert.equal(all.filter(n => n.textContent === "Cognism").length, 1, "Planned rows never duplicate catalog routes");
  assert.ok(!/Pilot tested|Maintained operation/.test(text.replace("no route is pilot tested", "")));
});

test("a route paused by its own evidence offers no preparation", () => {
  const ui = page();
  for (const status of ["source_review_due", "jurisdiction_unsupported"]) {
    const all = descendants(ui.run(`workState = {sender: {kind: "fake", configured: true, simulated: true, broker_sending: true}, workflow: {plan: [], paused: false, case_ids: []}};
      executionPanel({id: "c1", version: 1, broker: "cognism", execution_status: "${status}", next_step: "Synthetic reason for ${status}.", execution: null},
        {limits: "l", automation: "a"})`));
    assert.ok(all.some(n => n.textContent === "Synthetic reason for " + status + "."));
    assert.ok(!all.some(n => /Prepare/.test(n.textContent || "")), status);
    assert.ok(all.some(n => n.textContent === "Your email to cognism"));
  }
});

test("owner-email history shows the stored message only while open and clears on lock", () => {
  const ui = page();
  ui.run(`workState = {catalog: [{id: "cognism", name: "Cognism"}, {id: "apollo", name: "Apollo"}]};
    submissionState = {histories: {}, entries: [], emails: [
      {case_id: "c1", broker: "cognism", revision: 1, status: "transport_accepted", prepared_at: "2026-10-08T12:00:00+00:00",
       contract: {id: "cognism-delete-v1", version: 1, purpose: "Synthetic purpose", entity: "Synthetic entity", checked: "2026-10-08", jurisdiction_basis: "Synthetic basis"},
       message: {from: "email-canary@example.invalid", to: "privacy@broker.invalid", subject: "Subject", body: "Name: Email Canary"},
       selected: ["email", "full_name", "us_state"], approved_at: "2026-10-08T12:05:00+00:00", dispatched_at: "2026-10-08T12:06:00+00:00", next_step: "Watch your inbox.",
       result: {outcome: "accepted", reason: "provider_accepted", at: "2026-10-08T12:06:01+00:00", provider_message_id: "fake-1"}},
      {case_id: "c2", broker: "apollo", revision: 1, status: "prepared", prepared_at: "2026-10-07T12:00:00+00:00", contract: null,
       message: {from: "older-canary@example.invalid", to: "privacy@other.invalid", subject: "S", body: "B"}, selected: ["email"],
       approved_at: null, dispatched_at: null, next_step: "n", result: null}]};
    root.append(renderSubmissions());`);
  const text = () => descendants(ui.elements["#private-app"]).map(n => n.textContent).join(" ");
  assert.ok(text().includes("History"));
  assert.ok(!text().includes("email-canary") && !text().includes("Email Canary"));
  const [newer, older] = descendants(ui.elements["#private-app"]).filter(n => n.tag === "details" && /timeline-row/.test(n.className));
  newer.open = true; newer.listeners.toggle();
  assert.ok(text().includes("email-canary@example.invalid") && text().includes("Name: Email Canary"));
  assert.ok(text().includes("cognism-delete-v1"));
  assert.ok(text().includes("fake-1"));
  older.open = true; older.listeners.toggle();
  assert.ok(text().includes("Recorded before contract details were kept"));
  newer.open = false; newer.listeners.toggle();
  assert.ok(!text().includes("email-canary"));
  ui.run("wipe();");
  assert.ok(!text().includes("older-canary"));
});

test("each email records how the owner uses it, starting as not sure", () => {
  const ui = page();
  ui.run(`record = {profile: null, version: 0}; root.append(renderProfile());`);
  const all = () => descendants(ui.elements["#private-app"]);
  all().find(n => n.textContent === "Add another email").listeners.click();
  const label = all().find(n => n.textContent === "Type of address");
  const select = label.children.find(n => n.tag === "select");
  assert.deepEqual(select.children.map(o => o.value), ["unknown", "professional", "personal"]);
  assert.deepEqual(select.children.map(o => o.textContent), ["Not sure", "Work", "Personal"]);
  assert.ok(all().some(n => n.textContent === "Status") && !all().some(n => n.textContent === "Use"));
  assert.equal(select.value, "unknown", "Email use is never pre-filled from the address");
  const draft = ui.run("newIdentifier('emails')");
  assert.equal(draft.use, "unknown");
  assert.equal(ui.run("newIdentifier('phones')").use, undefined);
  select.value = "professional"; select.listeners.change();
  assert.equal(ui.run("identityDirty"), true);
});

test("a lost local server is explained and errors take focus next to the user", async () => {
  const ui = page();
  await assert.rejects(ui.run("api('/api/status')"), /local server is not responding.*nothing is retried automatically/);
  const box = ui.elements["#private-error"];
  let focused = false, scrolled = false;
  box.focus = () => {focused = true;}; box.scrollIntoView = () => {scrolled = true;};
  await ui.run("run(async () => {throw new Error('Synthetic refusal');})");
  assert.equal(box.textContent, "Synthetic refusal");
  assert.equal(box.attributes.tabindex, "-1");
  assert.ok(focused && scrolled, "The error is focused and scrolled into view");
});

test("the route table names existing emails instead of calling the route ready", () => {
  const ui = page();
  const row = state => ui.run(`workState={sender:{kind:"fake",broker_sending:true},workflow:{drop:{state:"not_eligible",url:"https://privacy.ca.gov/drop/"},case_ids:["c1"],paused:false,counts:{},items:[],external:[],
    plan:[{broker:"apollo",name:"Apollo",state:"${state}",missing:[],route_issue:null}]}};root.replaceChildren(renderBatch());
    [...root.children].length`) && descendants(ui.elements["#private-app"]).filter(n => n.tag === "td").map(n => n.textContent).join(" ");
  assert.match(row("email_already_sent"), /An email to this broker was sent; see its case/);
  assert.match(row("email_outcome_uncertain"), /uncertain; settle it in its case/);
  assert.match(row("ready_to_prepare_email"), /Velum can prepare the exact email. You approve it on its own/);
  assert.doesNotMatch(row("ready_to_prepare_email"), /handoff/);
});

test("uncertain emails offer three findings and a new request only with a duplicate acknowledgment", async () => {
  const ui = page();
  ui.run("var __calls = []; executionCommand = async (c, action, data) => { __calls.push({action, data}); };");
  const all = descendants(ui.run(`workState = {sender: {kind: "fake", broker_sending: true}, workflow: {plan: [], paused: false, case_ids: []}};
    executionPanel({id: "c1", version: 1, broker: "apollo", execution_status: "uncertain", next_step: "x",
      execution: {message: {from: "a@example.invalid", to: "b@example.invalid", subject: "S", body: "B"}, contract_id: "x", fingerprint: "f", result: null}},
      {limits: "l", automation: "a"})`));
  const select = all.find(n => n.tag === "select");
  assert.deepEqual(select.children.map(o => o.value), ["sent_found", "broker_replied", "not_found_in_sent"]);
  assert.ok(all.some(n => /only a rejection from your mail provider proves/.test(n.textContent || "")));
  const again = all.find(n => n.tag === "form" && descendants(n).some(x => x.textContent === "Prepare a new request anyway"));
  const risk = descendants(again).find(n => n.type === "checkbox");
  risk.checked = true;
  await again.listeners.submit({preventDefault() {}});
  await new Promise(r => setTimeout(r, 0));
  const prepared = ui.run("__calls").find(c => c.action === "prepare");
  assert.deepEqual(JSON.parse(JSON.stringify(prepared.data)), {drop_acknowledged: false, duplicate_acknowledged: true});
  assert.ok(!all.some(n => n.textContent === "Record reply"), "No reply form until the email is confirmed sent");
});

test("sent emails and manual submissions share the reply form, with an optional received date", async () => {
  const ui = page();
  ui.run("var __calls = []; command = async (c, action, data) => { __calls.push({action, data}); };");
  const all = descendants(ui.run(`workState = {sender: {kind: "fake", broker_sending: true}, workflow: {plan: [], paused: false, case_ids: []}};
    executionPanel({id: "c1", version: 1, broker: "apollo", execution_status: "transport_accepted", next_step: "x",
      execution: {message: {from: "a@example.invalid", to: "b@example.invalid", subject: "S", body: "B"}, contract_id: "x", fingerprint: "f", result: null}},
      {limits: "l", automation: "a"})`));
  const form = all.find(n => n.tag === "form" && descendants(n).some(x => x.textContent === "Record reply"));
  const fields = descendants(form);
  const select = fields.find(n => n.tag === "select");
  assert.ok(select.children.some(o => o.value === "no_record_reported"));
  const date = fields.find(n => n.type === "date"), note = fields.find(n => n.tag === "textarea");
  select.value = "acknowledged"; note.value = "Synthetic reply";
  await form.listeners.submit({preventDefault() {}}); await new Promise(r => setTimeout(r, 0));
  date.value = "2026-10-08";
  await form.listeners.submit({preventDefault() {}}); await new Promise(r => setTimeout(r, 0));
  const [first, second] = JSON.parse(JSON.stringify(ui.run("__calls")));
  assert.deepEqual(first, {action: "response", data: {result: "acknowledged", note: "Synthetic reply"}});
  assert.deepEqual(second.data.received_on, "2026-10-08");
});

const settle = () => new Promise(resolve => setTimeout(resolve, 5));
function recordingApi(ui, replies) {
  ui.run(`var __calls = []; var __replies = ${JSON.stringify(replies)};
    api = async (path, body) => { __calls.push({path, body}); return JSON.parse(JSON.stringify(__replies[path] || {})); };`);
  return () => ui.run("__calls");
}
const textOf = ui => descendants(ui.elements["#private-app"]).map(n => n.textContent).join(" ");

test("first run defaults to nothing kept and starts a session without saving", async () => {
  const ui = page();
  const calls = recordingApi(ui, {"/api/start": {session: "s1", profile: null, version: 0},
    "/api/status": {store: "session", locked: false, initialized: true, session_valid: true, remaining_seconds: 1800, vault_exists: false},
    "/api/cases": {cases: [], catalog: [], sender: {}}});
  ui.run("status = {store: null, locked: true, initialized: false, deletion_pending: false, vault_exists: false, ended: null}; renderLocked();");
  const all = () => descendants(ui.elements["#private-app"]);
  const radios = all().filter(n => n.type === "radio");
  assert.deepEqual(radios.map(r => [r.value, r.checked]), [["session", true], ["vault", false]]);
  assert.match(textOf(ui), /Is that zero risk\?.*No\. Your Mac can still hold traces/);
  const go = all().find(n => n.tag === "button" && n.textContent === "Start without saving");
  radios[1].listeners.change();
  assert.equal(go.textContent, "Create an encrypted record");
  radios[0].listeners.change();
  go.listeners.click();
  await settle();
  assert.equal(calls()[0].path, "/api/start");
  assert.equal(ui.run("session"), "s1");
  const bar = descendants(ui.elements["#app-header"]);
  assert.ok(bar.some(n => n.textContent === "Session only: nothing is kept"), "The slim header names the mode");
  assert.ok(bar.some(n => n.tag === "button" && n.textContent === "End session"), "End session is its own control in the header");
  assert.equal(ui.elements["#before-start"].hidden, true, "The introduction steps aside once a session starts");
});

test("choosing an encrypted record asks for a passphrase and the recovery limits", () => {
  const ui = page();
  ui.run("status = {store: null, vault_exists: false, ended: null}; root.replaceChildren(createVaultScreen());");
  const all = descendants(ui.elements["#private-app"]);
  assert.equal(all.filter(n => n.type === "password").length, 2);
  assert.match(textOf(ui), /there is no recovery/i);
});

test("ending a session is one screen, one button and one result", async () => {
  const ui = page();
  const ended = {store: null, locked: true, initialized: false, deletion_pending: false, vault_exists: false, ended: {reason: "ended", revoked: false}};
  const calls = recordingApi(ui, {"/api/end": {...ended, revoked: false}, "/api/status": ended});
  ui.run(`session = "s1"; record = {profile: null, version: 0}; status = {store: "session", session_valid: true, locked: false};
    workState = {sender: {account: "owner@example.invalid"}, cases: [], catalog: []}; workspaceView = "end"; renderWorkspace();`);
  assert.match(textOf(ui), /Your Gmail connection is disconnected, and Velum asks Google to revoke it/);
  assert.match(textOf(ui), /Sent folder and the copies brokers received/);
  descendants(ui.elements["#private-app"]).find(n => n.tag === "button" && n.textContent === "End session" && n.className === "danger").listeners.click();
  await settle();
  assert.deepEqual(calls().map(c => c.path)[0], "/api/end");
  assert.equal(ui.run("session"), null);
  assert.match(textOf(ui), /Session ended\. Everything Velum held for it was erased\./);
  assert.match(textOf(ui), /couldn’t reach Google/);
  assert.ok(descendants(ui.elements["#private-app"]).some(n => n.href === "https://myaccount.google.com/connections"));
});

test("deleting an encrypted record needs DELETE and the current version", async () => {
  const ui = page();
  const after = {store: null, locked: true, initialized: false, deletion_pending: false, vault_exists: false, ended: null};
  const calls = recordingApi(ui, {"/api/delete": {...after, revoked: true}, "/api/status": after});
  ui.run(`session = "s1"; record = {profile: {}, version: 3}; status = {store: "vault"}; workState = {sender: {}}; root.replaceChildren(renderDelete());`);
  assert.doesNotMatch(textOf(ui), /Gmail connection/, "No Gmail line without a connection");
  const form = descendants(ui.elements["#private-app"]).find(n => n.tag === "form");
  descendants(form).find(n => n.tag === "input").value = "DELETE";
  form.listeners.submit({preventDefault() {}});
  await settle();
  assert.deepEqual(JSON.parse(JSON.stringify(calls()[0])), {path: "/api/delete", body: {confirmation: "DELETE", version: 3}});
  assert.match(textOf(ui), /Everything was erased/);
  assert.match(textOf(ui), /Google confirmed it revoked/);
});

test("the idle warning counts down without replacing its button, then clears", () => {
  const ui = page();
  const box = ui.elements["#private-idle"];
  ui.run(`session = "s1"; status = {store: "session", remaining_seconds: 45}; renderIdle();`);
  assert.equal(box.hidden, false);
  assert.match(box.children[0].textContent, /This session ends in 0:45, and everything Velum holds for it is erased/);
  const keep = box.children[1];
  assert.equal(keep.textContent, "Keep working");
  ui.run("status.remaining_seconds = 44; renderIdle();");
  assert.equal(box.children[1], keep, "The focused button stays in place");
  assert.match(box.children[0].textContent, /0:44/);
  ui.run("status.remaining_seconds = 900; renderIdle();");
  assert.equal(box.hidden, true);
  ui.run(`status = {store: "vault", remaining_seconds: 30}; renderIdle();`);
  assert.match(box.children[0].textContent, /Your encrypted record locks in 0:30/);
});

test("hiding the page no longer locks or clears it", () => {
  const source = fs.readFileSync(path.join(__dirname, "../privacy_cleanup/static/private.js"), "utf8");
  assert.doesNotMatch(source, /document\.hidden\s*&&\s*session/);
  assert.match(source, /never ends a session/);
});

test("a session-only approval warns that earlier sessions are invisible", () => {
  const ui = page();
  const panel = store => descendants(ui.run(`status = {store: "${store}"}; workState = {sender: {kind: "fake", configured: true, simulated: true, broker_sending: true}, workflow: {plan: [], paused: false, case_ids: []}};
    executionPanel({id: "c1", version: 1, broker: "apollo", execution_status: "prepared", next_step: "x",
      execution: {message: {from: "owner@example.invalid", to: "privacy@broker.invalid", subject: "S", body: "B"}, contract_id: "synthetic-v1", fingerprint: "f", approval: null, result: null}},
      {limits: "l", automation: "a"})`)).map(n => n.textContent).join(" ");
  assert.match(panel("session"), /can’t see earlier ones/);
  assert.doesNotMatch(panel("vault"), /can’t see earlier ones/);
});

const approvedPanel = (ui, method) => ui.run(`sendMethod = ${JSON.stringify(method)}; status = {store: "session"};
  workState = {sender: {kind: "gmail", configured: true, simulated: false, broker_sending: false, account: "owner@example.invalid"}, workflow: {plan: [], paused: false, case_ids: ["c1"]}};
  executionPanel({id: "c1", version: 4, broker: "apollo", execution_status: "approved", next_step: "x",
    execution: {message: {from: "owner@example.invalid", to: "privacy@broker.invalid", subject: "Delete my data & more",
      body: "Line one\\nName: Avery Example"}, contract_id: "synthetic-v1", fingerprint: "f1", approval: {expires_at: "t"}, result: null}},
    {limits: "l", automation: "a"})`);

test("an approved email asks how to send before offering any send button", () => {
  const ui = page();
  const all = descendants(approvedPanel(ui, null));
  assert.ok(all.some(n => n.textContent === "Choose how to send"));
  assert.ok(!all.some(n => n.textContent === "Send this email now" || n.textContent === "I sent it"));
});

test("sending it yourself opens the exact email in the mail app and records the owner's report", async () => {
  const ui = page();
  ui.run("var __calls = []; executionCommand = async (c, action, data) => { __calls.push({action, data}); };");
  const all = descendants(approvedPanel(ui, "self"));
  const open = all.find(n => n.textContent === "Open in my mail app");
  assert.equal(open.tag, "a");
  assert.equal(open.href, "mailto:privacy@broker.invalid?subject=Delete%20my%20data%20%26%20more&body=Line%20one%0D%0AName%3A%20Avery%20Example");
  assert.ok(["Copy address", "Copy subject", "Copy body"].every(label => all.some(n => n.textContent === label)));
  assert.ok(!all.some(n => n.textContent === "Send this email now"));
  all.find(n => n.textContent === "I sent it").listeners.click();
  await settle();
  all.find(n => n.textContent === "I’m not sure it went").listeners.click();
  await settle();
  assert.deepEqual(JSON.parse(JSON.stringify(ui.run("__calls"))),
    [{action: "self_sent", data: {fingerprint: "f1", result: "sent"}}, {action: "self_sent", data: {fingerprint: "f1", result: "unsure"}}]);
});

test("the sending choice compares what each option needs, holds and keeps", () => {
  const ui = page();
  const choice = store => {
    ui.run(`status = {store: "${store}"}; workState = {sender: {kind: "gmail", broker_sending: false}, workflow: {items: [{id: "c1", state: "email_approved"}, {id: "c2", state: "email_approved"}]}};
      root.replaceChildren(renderSendChoice());`);
    return descendants(ui.elements["#private-app"]);
  };
  const session = choice("session");
  const text = session.map(n => n.textContent).join(" ");
  assert.match(text, /You approved 2 emails/);
  assert.equal(session.filter(n => n.className === "send-option").length, 3);
  assert.match(text, /No email permission at all/);
  assert.match(text, /waits for the reviewed pilot/);
  assert.match(text, /each email comes from you, not from Velum/);
  assert.equal(session.find(n => n.textContent === "Let Velum send them").disabled, true);
  assert.equal(choice("vault").filter(n => n.className === "send-option").length, 2);
});

const HOME = {counts: {do: 1, review: 1, waiting: 1, recorded: 1}, items: [
  {case_id: "c1", broker: "hunter", group: "do", label: "Uncertain", tone: "uncertain", detail: "It may or may not have reached the broker.", date: "2026-10-02", source: "attempt"},
  {case_id: "c2", broker: "contactout", group: "review", label: "Ready to review", tone: "review", detail: "Review the exact request.", date: null, source: null},
  {case_id: "c3", broker: "cognism", group: "waiting", label: "Waiting on broker", tone: "waiting", detail: "You chose a date to check again.", date: "2026-10-02T15:00:00+00:00", source: "sent", check_on: "2026-11-09"},
  {case_id: "c4", broker: "apollo", group: "recorded", label: "Broker reports deletion", tone: "done", detail: "This is the broker’s own report, not proof.", date: "2026-10-06", source: "reply you recorded"}]};
const CATALOG = [{id: "hunter", name: "Hunter"}, {id: "contactout", name: "ContactOut"}, {id: "cognism", name: "Cognism, Inc; test"}, {id: "apollo", name: "Apollo"}];

test("home groups what needs you, what is ready, waiting and recorded, with tab counts", () => {
  const ui = page();
  ui.run(`session = "s1"; record = {profile: {}, version: 1}; status = {store: "vault"}; workspaceView = "home";
    workState = {attention: ${JSON.stringify(HOME)}, catalog: ${JSON.stringify(CATALOG)}, cases: [], sender: {}}; renderWorkspace();`);
  const all = descendants(ui.elements["#private-app"]), text = all.map(n => n.textContent).join(" | ");
  assert.ok(all.some(n => n.textContent === "One thing needs you"));
  assert.ok(["You need to do", "Ready to review", "Waiting on the broker", "Outcome recorded"].every(t => all.some(n => n.textContent === t)));
  const tabs = descendants(ui.elements["#app-header"]).filter(n => n.className === "tab").map(n => n.textContent);
  assert.deepEqual(tabs, ["Home (1)", "Your requests (1)", "My information", "History", "Coverage"]);
  assert.equal(descendants(ui.elements["#app-header"]).find(n => n.textContent === "Home (1)").attributes["aria-current"], "page");
  assert.ok(all.some(n => n.className === "pill tone-uncertain" && n.textContent === "Uncertain"));
  assert.doesNotMatch(text, /overdue/i);
  ui.run("var __view = null; changeView = view => { __view = view; };");
  all.find(n => n.textContent === "Open and act").listeners.click();
  assert.equal(ui.run("selectedCase"), "c1");
  assert.equal(ui.run("__view"), "queue");
});

test("nothing needs your attention is a real, calm state", () => {
  const ui = page();
  const waitingOnly = {counts: {do: 0, review: 0, waiting: 1, recorded: 0}, items: [HOME.items[2]]};
  ui.run(`workState = {attention: ${JSON.stringify(waitingOnly)}, catalog: ${JSON.stringify(CATALOG)}}; root.replaceChildren(renderHome());`);
  const text = textOf(ui);
  assert.match(text, /Nothing needs your attention/);
  assert.match(text, /1 request is waiting on a broker\./);
  ui.run(`workState = {attention: {counts: {}, items: []}, catalog: []}; root.replaceChildren(renderHome());`);
  assert.match(textOf(ui), /Nothing needs your attention.*No requests yet/);
});

test("the calendar file holds only dates the owner chose, escaped, and says what it contains", () => {
  const ui = page();
  ui.run(`workState = {attention: ${JSON.stringify(HOME)}, catalog: ${JSON.stringify(CATALOG)}}; status = {store: "session"}; root.replaceChildren(renderHome());`);
  assert.match(textOf(ui), /saves a file with 1 date and the brokers’ names to your Downloads folder.*even after this session ends/);
  const ics = ui.run(`calendarFile(${JSON.stringify([HOME.items[2]])}, new Date("2026-10-11T00:00:00Z"))`);
  assert.match(ics, /^BEGIN:VCALENDAR\r\n/);
  assert.match(ics, /DTSTART;VALUE=DATE:20261109\r\n/);
  assert.ok(ics.includes("SUMMARY:Velum: check for a reply from Cognism\\, Inc\\; test\r\n"), "Commas and semicolons are escaped");
  assert.match(ics, /UID:c3-20261109@velum.invalid/);
  assert.doesNotMatch(ics, /hunter|apollo|contactout/i, "Only waiting requests with a chosen date are included");
});

test("the preview groups what typed information unlocks, without claiming a match", async () => {
  const ui = page();
  const result = {ready: true, changed: true, problem: null, rows: [
    {broker: "cognism", name: "Cognism", state: "ready_to_prepare_email", missing: []},
    {broker: "hunter", name: "Hunter", state: "needs_information", missing: ["Set one current email you can receive mail at to type of address Work in My information for this route"]},
    {broker: "lusha", name: "Lusha", state: "route_not_available_in_jurisdiction", missing: ["California only"]},
    {broker: "apollo", name: "Apollo", state: "email_already_sent", missing: []},
    {broker: "nuwber", name: "Nuwber", state: "research_only", missing: []}]};
  const calls = recordingApi(ui, {"/api/preview": result});
  ui.run(`workState = {sender: {}}; record = {profile: null, version: 0}; root.append(renderProfile());`);
  await settle();
  assert.equal(calls()[0].path, "/api/preview");
  const text = textOf(ui);
  assert.match(text, /Velum can prepare these.*Cognism/);
  assert.match(text, /May apply to you once you add something.*Hunter.*type of address Work/);
  assert.match(text, /Don’t apply where you live.*Lusha/);
  assert.match(text, /Already requested.*Apollo/);
  assert.match(text, /1 more give guidance only/);
  assert.match(text, /Preview of unsaved changes\. Preparing a request uses your saved information/);
  assert.match(text, /not whether a broker has your data\. Velum hasn’t searched for you\./);
  assert.doesNotMatch(text, /complete|score|\d+%/i);
});

test("a draft the server can't accept pauses the preview with its reason", async () => {
  const ui = page();
  recordingApi(ui, {"/api/preview": {ready: false, changed: true, problem: "Add a display name", rows: []}});
  ui.run(`workState = {sender: {}}; record = {profile: null, version: 0}; root.append(renderProfile());`);
  await settle();
  assert.match(textOf(ui), /Preview paused: Add a display name/);
});

test("a US resident picks a state from a list; other countries keep free text", () => {
  const ui = page();
  recordingApi(ui, {});
  ui.run(`workState = {sender: {kind: "gmail", account: "owner@example.invalid"}};
    record = {profile: {schema: 2, names: [], emails: [], addresses: [], phones: [], birth_date: "", residence: {country: "US", region: "California"}, self_adult: true}, version: 2};
    root.append(renderProfile());`);
  const all = () => descendants(ui.elements["#private-app"]);
  assert.match(textOf(ui), /Velum sends from your connected Gmail account, owner@example\.invalid/);
  const state = all().find(n => n.textContent === "Current state").children.find(n => n.tag === "select");
  assert.equal(state.value, "CA", "A saved state name maps to its code");
  assert.equal(state.children.length, 57);
  state.value = "TX"; state.listeners.change();
  const country = all().find(n => n.name === "country");
  country.value = "DE"; country.listeners.input();
  assert.ok(!all().some(n => n.textContent === "Current state"));
  assert.ok(all().some(n => n.name === "region" && n.tag === "input"));
});

// Batch 4, workstream 5: requests and sending.
const emailCase = (id, broker, statusName, extra = {}) => ({id, version: 1, broker, kind: "private_database", execution_status: statusName, next_step: "Next for " + broker,
  broker_response: "unknown", history: [], match: "not_applicable", request_status: "not_prepared", visibility: "not_applicable",
  execution: {message: {from: "owner@example.invalid", to: "privacy@" + broker + ".invalid", subject: "Delete my data", body: "Body for " + broker},
    contract_id: "synthetic-" + broker + "-v1", contract_version: 1, contract: {checked: "2026-10-08"}, fingerprint: "fp-" + broker,
    fields: {full_name: "Avery Example", email: "owner@example.invalid"}, prepared_at: "2026-10-11T15:04:00+00:00", approval: null, state: "prepared", result: null, ...extra}});
const SEND_CATALOG = [{id: "apollo", name: "Apollo", readiness: "owner_email"}, {id: "lusha", name: "Lusha", readiness: "owner_email"}, {id: "hunter", name: "Hunter", readiness: "owner_email"}];
function sendingWorkspace(ui, cases, workflow = {}) {
  ui.run(`session = "s1"; record = {profile: {}, version: 1}; status = {store: "session"}; refresh = async () => {};
    workState = {sender: {kind: "fake", configured: true, simulated: true, broker_sending: true}, catalog: ${JSON.stringify(SEND_CATALOG)}, cases: ${JSON.stringify(cases)},
      workflow: Object.assign({drop: {state: "not_eligible", url: "https://privacy.ca.gov/drop/"}, case_ids: ${JSON.stringify(cases.map(c => c.id))}, paused: false, counts: {}, preparable: [], external: [], plan: [],
        items: ${JSON.stringify(cases.map(c => ({id: c.id, broker: c.broker, state: "email_" + c.execution_status})))}}, ${JSON.stringify(workflow)})};`);
}
const everything = ui => descendants(ui.elements["#private-app"]);
const named = (ui, text) => everything(ui).find(n => n.textContent === text);

test("a new batch reads as ready and prepare-all opens the approve-and-next review", async () => {
  const ui = page();
  sendingWorkspace(ui, [], {case_ids: ["x"], preparable: ["a1", "l1"]});
  ui.run(`var __flow = []; flowCommand = async (action, data) => { __flow.push(action);
    workState.cases = [${JSON.stringify(emailCase("a1", "apollo", "prepared"))}, ${JSON.stringify(emailCase("l1", "lusha", "prepared"))}];
    workState.workflow.case_ids = ["a1", "l1"]; workState.workflow.preparable = [];
    workState.workflow.items = [{id: "a1", state: "email_prepared"}, {id: "l1", state: "email_prepared"}]; };
    root.replaceChildren(renderBatch());`);
  const text = everything(ui).map(n => n.textContent).join(" ");
  assert.match(text, /Ready: each email still needs your approval/);
  assert.doesNotMatch(text, /starts paused/i);
  named(ui, "Prepare all ready emails (2)").listeners.click();
  await settle();
  assert.deepEqual(JSON.parse(JSON.stringify(ui.run("__flow"))), ["prepare_emails"]);
  assert.equal(ui.run("workspaceView"), "approve");
  assert.ok(named(ui, "Review your emails"));
  assert.ok(named(ui, "Private database request · Email 1 of 2"));
});

test("approve and next approves each email on its own, skips, and ends on choosing how to send", async () => {
  const ui = page();
  sendingWorkspace(ui, [emailCase("a1", "apollo", "prepared"), emailCase("l1", "lusha", "prepared")]);
  ui.run(`var __approvals = []; executionCommand = async (c, action, data) => { __approvals.push({id: c.id, action, data});
    if (data.acknowledged) { const x = workState.cases.find(k => k.id === c.id); x.execution_status = "approved"; x.execution.approval = {expires_at: "2026-10-12T15:04:00+00:00"}; } };
    startReview();`);
  const all = everything(ui), text = all.map(n => n.textContent).join(" ");
  assert.ok(named(ui, "Why does the email say I’m sending it myself?"));
  assert.match(text, /Shared with Apollo: your name and your email address. Nothing else./);
  assert.match(text, /can’t see earlier ones/);
  const details = all.filter(n => n.tag === "details").map(d => d.children[0].textContent);
  assert.ok(details.includes("Technical details"), "Contract ids and fingerprints sit in a collapsed area");
  const approve = named(ui, "Approve and next");
  assert.equal(approve.disabled, true, "Approval needs the exact-email consent first");
  const box = all.find(n => n.type === "checkbox");
  box.checked = true; box.listeners.change();
  assert.equal(approve.disabled, false);
  approve.listeners.click(); await settle();
  assert.deepEqual(JSON.parse(JSON.stringify(ui.run("__approvals"))), [{id: "a1", action: "approve", data: {fingerprint: "fp-apollo", acknowledged: true}}]);
  assert.ok(named(ui, "Private database request · Email 2 of 2"));
  assert.ok(named(ui, "Approve and finish"));
  named(ui, "Skip for now").listeners.click();
  assert.ok(named(ui, "1 email approved"));
  assert.ok(named(ui, "Choose how to send"));
  assert.match(everything(ui).map(n => n.textContent).join(" "), /Nothing has been sent yet/);
  named(ui, "Review skipped emails").listeners.click();
  assert.ok(named(ui, "Approve and finish"), "A skipped email can be reviewed again");
});

test("sending asks in the page with every recipient and sends only the listed emails", async () => {
  const ui = page();
  const source = fs.readFileSync(path.join(__dirname, "../privacy_cleanup/static/private.js"), "utf8");
  assert.doesNotMatch(source, /window\.confirm\("Send/, "No browser dialog guards a send");
  assert.doesNotMatch(source, /window\.confirm\([^)]*test email/, "The self-test is confirmed in the page too");
  const approved = broker => emailCase(broker[0] + "1", broker, "approved", {approval: {expires_at: "2026-10-12T15:04:00+00:00"}});
  sendingWorkspace(ui, [approved("apollo"), approved("lusha"), emailCase("h1", "hunter", "prepared")]);
  ui.run(`sendMethod = "velum"; var __flow = []; flowCommand = async (action, data) => { __flow.push({action, data}); };
    renderWorkspace = () => root.replaceChildren(renderBatch()); renderWorkspace();`);
  named(ui, "Send 2 approved emails").listeners.click();
  assert.ok(named(ui, "Send these 2 emails?"));
  const cells = everything(ui).filter(n => n.tag === "td").map(n => n.textContent);
  assert.ok(cells.includes("privacy@apollo.invalid") && cells.includes("privacy@lusha.invalid"));
  assert.ok(!cells.includes("privacy@hunter.invalid"), "A prepared but unapproved email is not listed");
  named(ui, "Cancel").listeners.click();
  assert.equal(named(ui, "Send these 2 emails?"), undefined);
  named(ui, "Send 2 approved emails").listeners.click();
  named(ui, "Send 2 emails").listeners.click(); await settle();
  assert.deepEqual(JSON.parse(JSON.stringify(ui.run("__flow"))), [{action: "dispatch", data: {fingerprints: ["fp-apollo", "fp-lusha"]}}]);
});

test("one email's send confirmation names its recipient before anything is sent", async () => {
  const ui = page();
  sendingWorkspace(ui, [emailCase("a1", "apollo", "approved", {approval: {expires_at: "2026-10-12T15:04:00+00:00"}})]);
  ui.run(`sendMethod = "velum"; var __sent = []; executionCommand = async (c, action, data) => { __sent.push({action, data}); };
    renderWorkspace = () => root.replaceChildren(executionPanel(workState.cases[0], {name: "Apollo", limits: "l", automation: "a"})); renderWorkspace();`);
  named(ui, "Send this email now").listeners.click();
  assert.ok(named(ui, "Send this email?"));
  assert.ok(everything(ui).some(n => n.tag === "td" && n.textContent === "privacy@apollo.invalid"));
  assert.deepEqual(JSON.parse(JSON.stringify(ui.run("__sent"))), [], "Opening the confirmation sends nothing");
  named(ui, "Send 1 email").listeners.click(); await settle();
  assert.deepEqual(JSON.parse(JSON.stringify(ui.run("__sent"))), [{action: "dispatch", data: {fingerprint: "fp-apollo"}}]);
});

test("an email case reads in plain words with local times and technical details folded away", () => {
  const ui = page();
  sendingWorkspace(ui, [emailCase("a1", "apollo", "transport_accepted", {state: "transport_accepted", dispatched_at: "2026-10-11T15:05:00+00:00",
    result: {outcome: "accepted", reason: "provider_accepted", at: "2026-10-11T15:05:00+00:00", provider_message_id: "pm-1"}})]);
  ui.run(`requirementsGuide = () => el("div"); workState.catalog[0] = Object.assign(workState.catalog[0], {sources: [], limits: "l", automation: "a", requirements: {inputs: []}});
    root.replaceChildren(caseDetail(workState.cases[0]));`);
  const all = everything(ui), text = all.map(n => n.textContent).join(" ");
  assert.ok(named(ui, "EMAIL REQUEST"));
  assert.ok(all.some(n => n.className === "pill tone-done" && n.textContent === "Sent · your mail provider accepted it"));
  assert.doesNotMatch(text, /Listing visibility/);
  assert.ok(text.includes(ui.run(`localTime("2026-10-11T15:05:00+00:00")`)));
  assert.notEqual(ui.run(`localTime("2026-10-11T15:05:00+00:00")`), "2026-10-11T15:05:00+00:00");
  const technical = all.filter(n => n.tag === "details" && n.children[0].textContent === "Technical details");
  assert.ok(technical.length >= 1);
  const outside = all.filter(n => n.textContent.includes("synthetic-apollo-v1") && !technical.some(t => descendants(t).includes(n)));
  assert.deepEqual(outside.map(n => n.tag), [], "Contract ids appear only under Technical details");
});

test("routes are grouped by what you can do, with ones that don't apply folded away", () => {
  const ui = page();
  sendingWorkspace(ui, [], {plan: [
    {broker: "apollo", name: "Apollo", state: "ready_to_prepare_email", missing: [], route_issue: null},
    {broker: "hunter", name: "Hunter", state: "needs_information", missing: ["Set one email to Work"], route_issue: null},
    {broker: "lusha", name: "Lusha", state: "route_not_available_in_jurisdiction", missing: ["Lusha covers California only"], route_issue: null},
    {broker: "nuwber", name: "Nuwber", state: "research_only", missing: [], route_issue: null}]});
  ui.run(`root.replaceChildren(renderBatch());`);
  const all = everything(ui), headings = all.filter(n => n.tag === "h4").map(n => n.textContent);
  assert.deepEqual(headings, ["Velum can prepare these · 1", "May apply to you once you add something · 1"]);
  const folded = all.filter(n => n.tag === "details" && /^(Don’t apply where you live|Not supported yet) · 1$/.test(n.children[0].textContent));
  assert.equal(folded.length, 2);
  assert.ok(descendants(folded[0]).some(n => n.textContent === "Lusha"));
});

test("the review queue lists each email in plain words and names a session-only store", () => {
  const ui = page();
  sendingWorkspace(ui, [emailCase("a1", "apollo", "transport_accepted"), emailCase("l1", "lusha", "uncertain")]);
  ui.run(`createCaseForm = () => el("form"); caseDetail = () => el("section"); workspaceView = "queue"; renderWorkspace();`);
  const all = everything(ui), text = all.map(n => n.textContent).join(" ");
  assert.match(text, /Your requests · this session only/);
  assert.ok(all.some(n => n.className === "pill tone-done" && n.textContent === "Sent · your mail provider accepted it"));
  assert.ok(all.some(n => n.className === "pill tone-uncertain" && n.textContent === "Not sure it was sent"));
  assert.doesNotMatch(text, /email transport accepted/);
});

// Batch 4, workstream 6: one history timeline.
test("history is one timeline of emails, forms and requests made elsewhere, with shared filters", () => {
  const ui = page();
  ui.run(`workState = {catalog: [{id: "epsilon", name: "Epsilon"}, {id: "apollo", name: "Apollo"}],
    cases: [{id: "c2", broker: "apollo", review_on: "2026-11-01", due: false}],
    attention: {items: [{case_id: "c2", group: "waiting"}, {case_id: "c1", group: "review"}]},
    workflow: {external_brokers: [{id: "drop", name: "California DROP"}], external: [{id: "x1", broker: "drop", purpose: "DROP deletion", date: "2026-10-01",
      date_precision: "approximate", state: "uncertain", history: [{at: "2026-10-02T09:00:00+00:00", state: "uncertain", note: "ElsewhereCanary note", provenance: "user_reported"}]}]}};
    submissionState = {histories: {c2: [{at: "2026-10-09T10:00:00+00:00", kind: "send_transport_accepted", note: "n", provenance: "transport_result"},
        {at: "2026-10-09T11:00:00+00:00", kind: "broker_acknowledged", note: "Ack", provenance: "user_reported"}]},
      entries: [{case_id: "c1", broker: "epsilon", revision: 1, current: true, next_step: "Approve it.", request_status: "prepared", attempts: [], broker_response: "unknown", visibility: "not_applicable",
        request: {prepared_at: "2026-10-05T12:00:00+00:00", snapshot: {purpose: "Delete", route: {destination: "https://example.invalid", method: "manual_web_form"}, fields: {first_name: "FormCanary"}, identifiers: {}}}}],
      emails: [{case_id: "c2", broker: "apollo", revision: 1, current: true, status: "transport_accepted", prepared_at: "2026-10-09T09:00:00+00:00", dispatched_at: "2026-10-09T10:00:00+00:00",
        contract_id: "apollo-delete-v2", contract_version: 2, contract: null, fingerprint: "fp", message: {from: "mail-canary@example.invalid", to: "privacy@apollo.invalid", subject: "S", body: "B"},
        selected: ["email"], approved_at: "2026-10-09T09:30:00+00:00", next_step: "Watch your inbox.", result: null}]};
    root.append(renderSubmissions());`);
  const rows = () => everything(ui).filter(n => n.tag === "details" && /timeline-row/.test(n.className));
  const names = () => rows().map(r => r.children[0].children[1].textContent);
  const text = () => everything(ui).map(n => n.textContent).join(" ");
  assert.deepEqual(names(), ["Apollo", "Epsilon", "California DROP"], "Newest first across all three kinds");
  assert.ok(!/Canary/.test(text()), "Summaries carry no values");
  assert.ok(rows().every(r => r.children[0].children.at(-1).textContent === "Values hidden"));
  const control = label => everything(ui).find(n => n.tag === "label" && n.textContent === label).children[0];
  const set = (label, value) => { const c = control(label); c.value = value; c.listeners.change(); };
  set("Type", "external"); assert.deepEqual(names(), ["California DROP"]);
  set("Type", ""); set("Status", "uncertain"); assert.deepEqual(names(), ["California DROP"]);
  set("Status", "waiting"); assert.deepEqual(names(), ["Apollo"], "Status follows the attention groups");
  set("Status", ""); set("Search, including hidden values", "formcanary"); assert.deepEqual(names(), ["Epsilon"]);
  assert.ok(!/FormCanary/.test(text()), "A search match still hides values until opened");
  set("Search, including hidden values", ""); set("Sort", "oldest"); assert.deepEqual(names(), ["California DROP", "Epsilon", "Apollo"]);
  set("Sort", "newest");
  const apollo = rows()[0]; apollo.open = true; apollo.listeners.toggle();
  assert.ok(text().includes("mail-canary@example.invalid"));
  assert.ok(text().includes("Your mail provider accepted the email") && text().includes("Broker’s reply: acknowledged the request"));
  assert.ok(text().includes("Your mail provider’s answer"));
  assert.ok(!/send_transport_accepted|transport_result/.test(text()), "Event and source names are friendly");
  const form = rows()[1]; form.open = true; form.listeners.toggle();
  assert.ok(text().includes("First name") && text().includes("FormCanary"));
  ui.run("wipe();");
  assert.ok(!/Canary/.test(text()));
});

// Batch 4, workstream 7: coverage and layout.
test("the slim header holds five tabs and a separate Lock, and Help carries the guides until the record locks", () => {
  const ui = page();
  ui.run(`session = "s1"; record = {profile: {}, version: 1}; status = {store: "vault"}; workspaceView = "help";
    workState = {attention: {counts: {}, items: []}, catalog: [], cases: [], sender: {}}; renderWorkspace();`);
  const bar = descendants(ui.elements["#app-header"]);
  assert.ok(bar.some(n => n.textContent === "Encrypted record, unlocked"));
  assert.ok(bar.some(n => n.tag === "button" && n.textContent === "Lock"));
  assert.ok(!bar.some(n => n.textContent === "End session"));
  assert.equal(bar.find(n => n.textContent === "Help").attributes["aria-current"], "page");
  assert.ok(!bar.some(n => /Privacy\/settings|Review queue|Reload saved records/.test(n.textContent)), "Settings and reload left the tab row");
  const app = descendants(ui.elements["#private-app"]);
  for (const id of ["#drop-guide", "#user-guide", "#requirements-panel"]) assert.ok(app.includes(ui.elements[id]), id + " is under Help");
  ui.run(`status = {store: "vault", vault_exists: true, initialized: true, locked: true}; wipe(); renderLocked();`);
  assert.equal(ui.elements["#before-start"].hidden, false);
  for (const id of ["#drop-guide", "#user-guide", "#requirements-panel"]) assert.equal(ui.elements[id].parent, ui.elements["#before-start"], id + " returns before start");
  assert.ok(!descendants(ui.elements["#app-header"]).some(n => n.className === "tab"), "The tabs leave with the session");
});

test("a result or error appears beside the control that caused it", async () => {
  const ui = page();
  ui.run(`refresh = async () => {}; const wrap = el("section"), form = el("form"), row = el("div", undefined, "actions");
    submitForm(form, "Save synthetic thing", async () => { throw new Error("Synthetic refusal"); });
    row.append(button("Do synthetic thing", () => run(async () => { message.textContent = "Synthetic done."; placeBanners(); })));
    wrap.append(form, row); root.append(wrap); var __wrap = wrap, __form = form, __row = row;`);
  ui.run(`__form.listeners.submit({preventDefault() {}})`); await settle();
  const kids = () => ui.run("__wrap.children"), inForm = ui.run("__form.children");
  assert.equal(inForm[inForm.findIndex(n => n.textContent === "Save synthetic thing") + 1], ui.elements["#private-error"], "The error sits just below the button that failed");
  assert.equal(ui.elements["#private-error"].textContent, "Synthetic refusal");
  descendants(ui.run("__row")).find(n => n.textContent === "Do synthetic thing").listeners.click(); await settle();
  const after = kids(), at = after.indexOf(ui.run("__row"));
  assert.equal(after[at + 2], ui.elements["#private-message"], "The result follows the row of buttons that acted");
  assert.equal(ui.elements["#private-message"].textContent, "Synthetic done.");
});

test("the capability matrix wraps into cards, says who each route covers and highlights yours", () => {
  const ui = page();
  const cat = [{id: "apollo", name: "Apollo", capability: "automated_simulation", method: "owner_email", purpose: "Delete", checked: "2026-10-08", covers: "Anyone, wherever they live", freshness: {fresh: true, checked: "2026-10-08", review_by: "2026-11-07"}},
    {id: "lusha", name: "Lusha", capability: "automated_simulation", method: "owner_email", purpose: "Erase", checked: "2026-10-08", covers: "Residents of California", freshness: {fresh: true}},
    {id: "epsilon", name: "Epsilon", capability: "local_preparation", method: "manual_web_form", purpose: "Delete", checked: "2026-10-07", covers: "US residents", freshness: {fresh: true}}];
  const plan = [{broker: "apollo", name: "Apollo", state: "ready_to_prepare_email", missing: []}, {broker: "lusha", name: "Lusha", state: "route_not_available_in_jurisdiction", missing: ["x"]},
    {broker: "epsilon", name: "Epsilon", state: "needs_information", missing: ["Add a first name"]}];
  const all = descendants(ui.run(`capabilityMatrix(${JSON.stringify(cat)}, ${JSON.stringify(plan)})`)), text = all.map(n => n.textContent).join(" ");
  const cards = all.filter(n => n.tag === "article");
  assert.equal(cards.length, 3);
  assert.deepEqual(cards.map(c => c.className), ["route-card eligible", "route-card", "route-card"]);
  assert.match(text, /1 route is available to you now/);
  assert.ok(text.includes("Anyone, wherever they live") && text.includes("Residents of California"));
  assert.ok(all.some(n => n.textContent === "Doesn’t apply where you live") && all.some(n => n.textContent === "What it needs: Add a first name"));
  assert.ok(text.includes("you submit the broker’s form yourself"), "Each level is explained in a line");
  assert.ok(!all.some(n => n.tag === "table"), "Cards wrap; no wide table");
  const locked = descendants(ui.run(`capabilityMatrix(${JSON.stringify(cat)})`)).map(n => n.textContent).join(" ");
  assert.doesNotMatch(locked, /For you|available to you/, "Before unlocking there is no personal eligibility");
});

// Fresh review of workstreams 6 and 7.
test("header controls are disabled while an action runs, as the old toolbar was", async () => {
  const ui = page();
  ui.run(`session = "s1"; record = {profile: {}, version: 1}; status = {store: "session"}; workspaceView = "home"; refresh = async () => {};
    workState = {attention: {counts: {}, items: []}, catalog: [], cases: [], sender: {}}; renderWorkspace();`);
  descendants(ui.elements["#app-header"]).forEach(n => { n.isConnected = true; });  // As in a real page.
  ui.run(`var __release; run(() => new Promise(r => { __release = r; }));`);
  const tab = () => descendants(ui.elements["#app-header"]).find(n => n.textContent === "History");
  assert.equal(tab().disabled, true);
  ui.run("__release()"); await settle();
  assert.ok(!tab().disabled, "Restored afterwards");
});

test("before information is saved, the highlighted tab is the screen actually shown", () => {
  const ui = page();
  ui.run(`session = "s1"; record = {profile: null, version: 0}; status = {store: "session"}; workspaceView = "coverage";
    workState = {attention: {counts: {}, items: []}, catalog: [], cases: [], sender: {}}; renderProfile = () => el("section"); renderWorkspace();`);
  const current = descendants(ui.elements["#app-header"]).filter(n => n.attributes?.["aria-current"] === "page").map(n => n.textContent);
  assert.deepEqual(current, ["My information"]);
});

test("opening the review keeps the prepare-all summary, including why an email was skipped", async () => {
  const ui = page();
  sendingWorkspace(ui, [], {case_ids: ["x"], preparable: ["a1"]});
  ui.run(`flowCommand = async () => { workState.cases = [${JSON.stringify(emailCase("a1", "apollo", "prepared"))}]; workState.workflow.case_ids = ["a1"];
      workState.workflow.preparable = []; workState.workflow.items = [{id: "a1", state: "email_prepared"}];
      message.textContent = "Prepared 1 email. Not prepared: Lusha (synthetic reason)."; };
    root.replaceChildren(renderBatch());`);
  named(ui, "Prepare all ready emails (1)").listeners.click(); await settle();
  assert.equal(ui.run("workspaceView"), "approve");
  assert.match(ui.elements["#private-message"].textContent, /Not prepared: Lusha \(synthetic reason\)/);
});

test("history keeps an earlier email's real status, finds it as uncertain, and searches values only", () => {
  const ui = page();
  const earlier = {case_id: "c1", broker: "apollo", revision: 1, current: false, status: "uncertain", prepared_at: "2026-10-01T10:00:00+00:00", dispatched_at: "2026-10-01T10:01:00+00:00",
    contract_id: "x", contract: null, fingerprint: "f1", message: {from: "a@example.invalid", to: "privacy@apollo.invalid", subject: "S", body: "B"}, selected: [], approved_at: null, next_step: "n", result: null};
  const unused = {...earlier, revision: 2, status: "superseded", prepared_at: "2026-10-02T10:00:00+00:00", dispatched_at: null};
  const now = {...earlier, revision: 3, current: true, status: "prepared", prepared_at: "2026-10-03T10:00:00+00:00", dispatched_at: null};
  ui.run(`workState = {catalog: [{id: "apollo", name: "Apollo"}], cases: [], attention: {items: []}, workflow: {external_brokers: [], external: []}};
    submissionState = {histories: {}, entries: [], emails: ${JSON.stringify([earlier, unused, now])}}; root.append(renderSubmissions());`);
  const pills = () => everything(ui).filter(n => /^pill tone-/.test(n.className || "") && n.parent?.tag === "summary").map(n => n.textContent);
  assert.deepEqual(pills(), ["Ready for your review", "Earlier version", "Not sure it was sent"]);
  const control = label => everything(ui).find(n => n.tag === "label" && n.textContent === label).children[0];
  const set = (label, value) => { const c = control(label); c.value = value; c.listeners.change(); };
  set("Status", "uncertain"); assert.deepEqual(pills(), ["Not sure it was sent"], "An earlier uncertain email is still uncertain");
  set("Status", ""); set("Search, including hidden values", "subject");
  assert.deepEqual(pills(), [], "Field names are not searched");
});

test("history date filters use the local day shown on each row", () => {
  const zone = process.env.TZ;
  process.env.TZ = "America/Los_Angeles";
  try {
    const ui = page();
    const late = {case_id: "c1", broker: "apollo", revision: 1, current: true, status: "transport_accepted", prepared_at: "2026-10-09T02:30:00+00:00", dispatched_at: "2026-10-09T03:00:00+00:00",
      contract_id: "x", contract: null, fingerprint: "f", message: {from: "a", to: "b", subject: "S", body: "B"}, selected: [], approved_at: null, next_step: "n", result: null};
    ui.run(`workState = {catalog: [{id: "apollo", name: "Apollo"}], cases: [], attention: {items: []}, workflow: {external_brokers: [], external: []}};
      submissionState = {histories: {}, entries: [], emails: [${JSON.stringify(late)}]}; root.append(renderSubmissions());`);
    const rows = () => everything(ui).filter(n => n.tag === "details" && /timeline-row/.test(n.className)).length;
    const control = label => everything(ui).find(n => n.tag === "label" && n.textContent === label).children[0];
    for (const label of ["From", "Through"]) { const c = control(label); c.value = "2026-10-08"; c.listeners.change(); }
    assert.equal(rows(), 1, "Sent on the evening of 8 October locally, though 9 October in UTC");
  } finally { if (zone === undefined) delete process.env.TZ; else process.env.TZ = zone; }
});

// Both-modes acceptance walkthrough (2026-10-12): defects found and fixed.
test("home shows local dates and plain source words, never raw dates or internal names", () => {
  const ui = page();
  ui.run(`session = "s1"; record = {profile: {}, version: 1}; status = {store: "vault"}; workspaceView = "home";
    workState = {attention: ${JSON.stringify(HOME)}, catalog: ${JSON.stringify(CATALOG)}, cases: [], sender: {}}; renderWorkspace();`);
  const text = textOf(ui);
  assert.ok(text.includes("Sent " + ui.run(`localDate("2026-10-02T15:00:00+00:00")`)));
  assert.ok(text.includes("You’ll check again on " + ui.run(`localDate("2026-11-09")`)));
  assert.ok(text.includes("Tried to send ") && text.includes("Reply recorded "));
  assert.doesNotMatch(text, /Since 20\d\d-|· attempt|· sent\b|2026-10-02T/);
});

test("a case's dated history uses plain event and source names", () => {
  const ui = page();
  sendingWorkspace(ui, [emailCase("a1", "apollo", "transport_accepted", {state: "transport_accepted"})]);
  ui.run(`workState.cases[0].history = [{at: "2026-10-12T10:00:00+00:00", kind: "send_transport_accepted", note: "n", provenance: "transport_result"},
      {at: "2026-10-12T11:00:00+00:00", kind: "send_duplicate_risk_acknowledged", note: "d", provenance: "user_reported"}];
    requirementsGuide = () => el("div"); workState.catalog[0] = Object.assign(workState.catalog[0], {sources: [], limits: "l", automation: "a", requirements: {inputs: []}});
    root.replaceChildren(caseDetail(workState.cases[0]));`);
  const text = textOf(ui);
  assert.ok(text.includes("Your mail provider accepted the email") && text.includes("You accepted a possible duplicate request"));
  assert.ok(text.includes("Your mail provider’s answer") && text.includes("Your report"));
  assert.doesNotMatch(text, /send transport accepted|Source: transport result/);
});

test("saving a case action says where it was kept, and never claims encryption in a session", async () => {
  const ui = page();
  ui.run(`api = async () => ({cases: [], catalog: []}); renderWorkspace = () => {};`);
  for (const [store, words] of [["session", "Saved for this session. Nothing was sent."], ["vault", "Saved in your encrypted record. Nothing was sent."]]) {
    ui.run(`status = {store: "${store}"};`);
    await ui.run(`command({id: "c1", version: 1}, "note", {note: "n"}, generation)`);
    assert.equal(ui.elements["#private-message"].textContent, words);
  }
});

test("a lost server, a fresh page and a deleted record each read accurately", () => {
  const ui = page();
  assert.equal(ui.run("workspaceView"), "home", "Home is the landing view once information exists");
  ui.run("showUnavailable()");
  assert.doesNotMatch(textOf(ui), /vault is unavailable/i);
  assert.match(textOf(ui), /local server isn’t responding/);
  ui.run(`status = {store: null, vault_exists: false, ended: null}; endNote = {reason: "deleted", revoked: null}; renderLocked();`);
  assert.match(textOf(ui), /An empty database file, holding nothing about you, stays in Velum’s folder/);
});

test("restored history stays visibly stale and settings explains local recovery", () => {
  const ui = page();
  ui.run(`status={store:'vault',locked:false}; record={profile:null}; workspaceView='settings';
    workState={recovery:{snapshot_at:'2026-10-17T00:00:00Z',reconciled_at:null}};
    renderSender=()=>el('div'); sendingSettings=()=>el('div'); renderDelete=()=>el('div');
    renderView(false);`);
  const texts=descendants(ui.elements['#private-app']).map(n=>n.textContent).join(' ');
  assert.match(texts,/History may omit later requests/);
  assert.match(texts,/New request approval and handoffs are blocked/);
  assert.match(texts,/velum recovery --help/);
  assert.match(texts,/Local deletion does not delete backup copies/);
});
