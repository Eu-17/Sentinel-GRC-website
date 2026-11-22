"use strict";

const demos = window.SENTINEL_DEMOS;
const byId = id => document.getElementById(id);
const svgNS = "http://www.w3.org/2000/svg";
const icons = {
    grid: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
    layers: "m12 3 9 5-9 5-9-5z M3 12l9 5 9-5 M3 16l9 5 9-5",
    shield: "m12 2 8 3v6c0 5-4 8-8 11-4-3-8-6-8-11V5z M8 12l3 3 5-6",
    pulse: "M2 13h5l3-8 4 15 3-9 2 2h3",
    panel: "M3 4h18v16H3z M9 4v16", file: "M5 2h9l5 5v15H5z M14 2v6h5 M8 13h8 M8 17h6",
    play: "m7 4 12 8-12 8z", cpu: "M6 6h12v12H6z M9 2v4 M15 2v4 M9 18v4 M15 18v4 M2 9h4 M2 15h4 M18 9h4 M18 15h4",
    radar: "M12 12 20 4 M17 4a9 9 0 1 0 4 7 M14 8a5 5 0 1 0 3 4",
    gauge: "M3 17a9 9 0 1 1 18 0 M12 15l5-6 M4 17h16",
};
const state = {sample: "ransomware", report: demos.ransomware.report, view: "soc",
    selected: "NET-SOC-101", live: false, uploads: false, maxUploadBytes: 0, busy: false, custom: null, pendingCapture: null,
    saved: null, savedCaptures: [], captureStorage: false, captureLibraryError: "",
    rules: null, rulesEditable: false, rulesError: "", ruleNotice: "", ruleSaving: false, ruleRevision: 0,
    reportRevision: 0, ruleDraft: null};

function el(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
}

function svgEl(tag, attrs) {
    const node = document.createElementNS(svgNS, tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    return node;
}

function icon(name) {
    const node = svgEl("svg", {viewBox: "0 0 24 24", class: "icon", "aria-hidden": "true"});
    node.append(svgEl("path", {d: icons[name]}));
    return node;
}

function button(text, cls, handler) {
    const node = el("button", cls, text);
    node.type = "button";
    node.addEventListener("click", handler);
    return node;
}

function link(text, href, cls = "source-link") {
    const node = el("a", cls, text);
    node.href = href;
    return node;
}

function message(text, error = false) {
    byId("status").textContent = text;
    byId("status").classList.toggle("error", error);
}

function metric(label, count, unit, note, symbol, color) {
    const card = el("div", "metric");
    const head = el("div", "metric-head");
    const stamp = el("span", "metric-icon " + color);
    stamp.append(icon(symbol));
    head.append(el("span", "metric-title", label), stamp);
    const value = el("div", "metric-value", count);
    if (unit) value.append(el("small", "", unit));
    card.append(head, value, el("div", "metric-foot", note));
    return card;
}

function plotTrace(active) {
    const svg = byId("trace");
    svg.replaceChildren();
    const frames = active.flatMap(item => item.flows).sort((a, b) => a.frame - b.frame).slice(0, 10);
    const last = frames.at(-1);
    const max = Math.max(1, ...frames.map(flow => flow.bytes));
    for (let y = 12; y < 104; y += 22) svg.append(svgEl("path", {d: "M0 " + y + "h420", class: "trace-grid"}));
    for (let x = 4; x < 420; x += 46) svg.append(svgEl("path", {d: "M" + x + " 0v104", class: "trace-grid"}));
    // Each impulse represents an actual matched frame. Height encodes its byte length.
    for (const [i, frame] of frames.entries()) {
        const x = 12 + i * 396 / Math.max(1, frames.length - 1);
        const y = 92 - frame.bytes / max * 73;
        svg.append(svgEl("path", {d: "M" + (x - 7) + " 94 L" + x + " " + y + " L" + (x + 7) + " 94 Z", class: "trace-area"}));
        svg.append(svgEl("path", {d: "M" + (x - 8) + " 94 H" + (x - 4) + " L" + x + " " + y + " L" + (x + 4) + " 94 H" + (x + 8), class: "trace-line"}));
        const point = svgEl("circle", {cx: x, cy: y, r: 2.5, class: "trace-point"});
        const title = svgEl("title", {});
        title.textContent = "Frame " + frame.frame + " · " + frame.bytes + " bytes";
        point.append(title);
        svg.append(point);
    }
    byId("trace-legend").textContent = frames.length ? "Frames " + frames[0].frame + "–" + last.frame : "No matching frames";
    byId("trace-span").textContent = frames.length ? "Peak " + max + " B" : "";
}

function section(label) {
    const node = el("section", "detail-section");
    node.append(el("h4", "detail-label", label));
    return node;
}

function flowTable(finding) {
    const details = el("details", "detail-section");
    details.append(el("summary", "", "Packet evidence · " + finding.flows.length + " of " + finding.count + " frames"));
    const scroll = el("div", "table-scroll");
    const table = el("table", "packet-table");
    const head = table.createTHead().insertRow();
    for (const label of ["Frame", "Source", "Destination", "Protocol", "Bytes"]) {
        const th = el("th", "", label);
        th.scope = "col";
        head.append(th);
    }
    const body = table.createTBody();
    for (const frame of finding.flows) {
        const row = body.insertRow();
        for (const value of [frame.frame, frame.source, frame.destination, frame.protocol, frame.bytes]) row.insertCell().textContent = value;
    }
    scroll.append(table);
    details.append(scroll);
    return details;
}

function renderSOC(detail, finding) {
    const notes = section("Analyst brief · " + finding.brief.source);
    notes.append(el("p", "", finding.brief.soc));
    detail.append(notes);
    if (!finding.count) return;
    detail.append(flowTable(finding));
    const block = section("Firewall proposal");
    block.append(el("p", "", "Host-local draft for analyst review. Check interface, chain order and business impact before use."));
    const commands = finding.firewall.join("\n");
    block.append(el("pre", "codebox", commands));
    block.append(button("Copy rules", "mini-button", async event => {
        const target = event.currentTarget;
        try {
            await navigator.clipboard.writeText(commands);
            target.textContent = "Copied";
        } catch {
            target.textContent = "Select the rules above to copy";
        }
    }));
    if (finding.address_count > 10) block.append(el("p", "muted", "Showing the first 10 addresses."));
    detail.append(block);
    if (finding.playbook.length) {
        const playbook = section("Containment checklist");
        const list = el("ol");
        for (const step of finding.playbook) list.append(el("li", "", step));
        playbook.append(list);
        detail.append(playbook);
    }
}

function renderGRC(detail, finding) {
    const risk = finding.risk;
    const notes = section("Executive brief · " + finding.brief.source);
    notes.append(el("p", "", finding.brief.grc));
    detail.append(notes);
    const scoring = section("Scenario risk · " + risk.score + "/25");
    scoring.append(el("p", "", "Baseline " + risk.baseline + "/25 · Inherent " + risk.inherent + "/25. The outlined cell marks inherent likelihood × impact."));
    const matrix = el("div", "matrix");
    matrix.setAttribute("aria-label", "Likelihood increases upwards. Impact increases to the right.");
    for (let likelihood = 5; likelihood >= 1; likelihood--) {
        for (let impact = 1; impact <= 5; impact++) {
            const value = impact * likelihood;
            const tone = value >= 20 ? "critical" : value >= 12 ? "high" : value >= 6 ? "moderate" : "low";
            const cell = el("span", tone, value);
            cell.title = "Likelihood " + likelihood + " × impact " + impact;
            cell.classList.toggle("selected", likelihood === risk.likelihood && impact === risk.impact);
            matrix.append(cell);
        }
    }
    scoring.append(matrix, el("p", "muted", "Likelihood increases upwards. Impact increases to the right."));
    detail.append(scoring);
    if (risk.controls.length) {
        const controls = section("ISO/IEC 27001:2022 · mapped controls");
        for (const control of risk.controls) {
            const row = el("div", "control-row");
            const header = el("div", "line-head");
            header.append(el("span", "tag " + (finding.count ? "alert" : "clear"), "Model " + control.state),
                el("strong", "", control.id + " · " + control.name));
            row.append(header, el("p", "", control.evidence));
            controls.append(row);
        }
        controls.append(el("p", "muted", "These outcomes describe the capture scenario. An organisation-wide audit requires additional evidence."));
        detail.append(controls);
    }
    if (risk.review) {
        const review = section("UK GDPR · assessment needed");
        review.append(el("p", "", risk.review), el("p", "", "Record when the organisation became aware of a personal data breach. If the breach is reportable, notify the ICO without undue delay and within 72 hours where feasible."),
            link("Read ICO breach guidance", "https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/personal-data-breaches-a-guide/"));
        detail.append(review);
    }
}

function trafficSummary(title, entries, label) {
    const panel = el("section", "overview-summary");
    panel.append(el("h3", "", title));
    if (!entries.length) {
        panel.append(el("p", "muted", "No data available."));
        return panel;
    }
    const list = el("dl", "overview-counts");
    for (const entry of entries) {
        list.append(el("dt", "mono", entry[label]), el("dd", "", entry.frames.toLocaleString() + " frames"));
    }
    panel.append(list);
    return panel;
}

function captureObservation(observation, findings) {
    const entry = el("article", "overview-observation");
    entry.append(el("h4", "", observation.title), el("p", "", observation.detail));
    const evidence = el("dl", "overview-evidence");
    if (observation.addresses.length) {
        evidence.append(el("dt", "", "Endpoints to review"), el("dd", "mono", observation.addresses.join(", ")));
    }
    if (observation.frames.length) {
        evidence.append(el("dt", "", "Example frames"), el("dd", "mono", observation.frames.join(", ")));
    }
    if (evidence.childElementCount) entry.append(evidence);

    const suggestions = observation.rule_ids.map(id => findings.find(finding => finding.id === id)).filter(Boolean);
    if (suggestions.length) {
        const actions = el("div", "actions overview-actions");
        for (const finding of suggestions) {
            actions.append(button("View " + finding.name, "secondary mini-button", () => {
                state.selected = finding.id;
                renderResults();
                byId("finding-" + finding.id).focus();
            }));
        }
        entry.append(actions);
    }
    if (observation.suggested_filter) {
        const draft = el("div", "overview-follow-up");
        const actions = el("div", "actions overview-actions");
        actions.append(button("Copy filter", "mini-button", async event => {
            const copy = event.currentTarget;
            try {
                await navigator.clipboard.writeText(observation.suggested_filter);
                copy.textContent = "Filter copied";
            } catch {
                copy.textContent = "Select the filter above to copy";
            }
        }));
        if (state.rulesEditable) {
            actions.append(button("New rule from filter", "secondary mini-button", () => {
                state.ruleDraft = {
                    name: observation.title,
                    summary: observation.detail,
                    filter: observation.suggested_filter,
                    controls: observation.controls,
                    severity: "Low",
                    protocol: "IP"
                };
                location.hash = "rules";
            }));
        }
        draft.append(el("h5", "detail-label", "Suggested Wireshark display filter"),
            el("pre", "codebox", observation.suggested_filter), actions);
        entry.append(draft);
    }
    if (observation.grc) {
        const followUp = el("div", "overview-follow-up");
        followUp.append(el("h5", "detail-label", "GRC & audit follow-up"), el("p", "", observation.grc));
        if (observation.controls?.length) {
            followUp.append(el("p", "overview-controls", observation.controls.map(control => control.join(" · ")).join(" | ")));
        }
        entry.append(followUp);
    }
    return entry;
}

function renderOverview({overview, findings, engine}) {
    byId("capture-overview").hidden = !overview && engine !== "TShark";
    const target = byId("overview-content");
    target.replaceChildren();
    if (!overview) {
        if (engine === "TShark") target.append(el("p", "muted overview-empty", "Traffic overview unavailable for this capture. Rule findings are shown below."));
        return;
    }
    const summaries = el("div", "overview-summaries");
    summaries.append(trafficSummary("Top protocols", overview.protocols, "name"),
        trafficSummary("Most active IP addresses", overview.endpoints, "address"));
    const observations = el("section", "overview-observations");
    observations.append(el("h3", "", "Activity to review"));
    if (overview.observations.length) {
        for (const observation of overview.observations) observations.append(captureObservation(observation, findings));
    } else {
        observations.append(el("p", "muted", "The overview checks found no unusual activity. Review the rule findings and compare traffic with your network baseline."));
    }
    target.append(summaries, observations);
}

function renderResults() {
    const {report, view} = state;
    const findings = report.findings;
    const active = findings.filter(item => item.count > 0);
    const finding = findings.find(item => item.id === state.selected) || active[0] || findings[0];
    state.selected = finding?.id;
    const count = active.reduce((sum, item) => sum + item.count, 0);
    const controls = new Set(active.flatMap(item => item.risk.controls.map(control => control.id)));
    const peak = Math.max(0, ...findings.map(item => item.risk.score));
    byId("metrics").replaceChildren(
        metric("Triggered rules", active.length, " / " + findings.length, "Detection coverage", "radar", ""),
        metric("Frame matches", count, "", report.frames + " total capture frames", "pulse", "blue"),
        metric("Peak risk", peak, " / 25", "Highest scenario score", "gauge", "amber"),
        metric("Flagged controls", controls.size, "", "Distinct Annex A controls", "shield", "lilac")
    );
    plotTrace(active);
    renderOverview(report);
    byId("capture-title").textContent = demos[state.sample]?.title || "Custom capture";
    byId("capture-file").textContent = state.saved?.name || state.custom?.name || report.capture;
    byId("capture-type").textContent = state.saved ? "SAVED CAPTURE" : state.custom ? "UPLOAD" : "DEMO PCAP";
    byId("engine-label").textContent = report.engine;
    byId("soc-view").setAttribute("aria-pressed", view === "soc");
    byId("grc-view").setAttribute("aria-pressed", view === "grc");
    byId("result-title").textContent = view === "soc" ? "Rule findings" : "Control assessment";
    byId("review-count").textContent = active.length + " of " + findings.length + " triggered";
    renderAppliedRules();
    const buttons = findings.map(item => {
        const node = button("", "finding", () => {
            state.selected = item.id;
            renderResults();
            byId("finding-" + item.id).focus({preventScroll: true});
        });
        node.id = "finding-" + item.id;
        node.setAttribute("aria-pressed", item.id === state.selected);
        const line = el("span", "line-head");
        line.append(el("small", "", item.id), el("span", "tag " + (item.count ? "alert" : "clear"), item.count ? item.severity : "No match"));
        node.append(line, el("strong", "", item.name), el("span", "muted", item.count + " matched frames"));
        return node;
    });
    byId("finding-list").replaceChildren(...buttons);
    const detail = byId("detail");
    if (!finding) {
        detail.replaceChildren(el("p", "", "No detection rules were available for this analysis."));
        return;
    }
    detail.replaceChildren(el("div", "eyebrow", finding.id), el("h3", "", finding.name));
    const tags = el("div", "result-meta");
    const technique = [finding.technique, finding.technique_name].filter(Boolean).join(" · ");
    if (technique) tags.append(el("span", "chip", technique));
    if (finding.tactic) tags.append(el("span", "chip", finding.tactic));
    if (tags.childElementCount) detail.append(tags);
    if (view === "soc") renderSOC(detail, finding);
    else renderGRC(detail, finding);
}

function renderAppliedRules() {
    const note = byId("applied-rules-note");
    const stale = state.reportRevision !== state.ruleRevision;
    if (stale) {
        note.textContent = "Rules changed after this analysis. Run analysis again to apply the current rules.";
    } else if (state.report.engine === "Fixture replay") {
        note.textContent = "This list shows the rules used to record the sample.";
    } else if (!state.report.findings.length) {
        note.textContent = "No rules were configured when this capture was analysed.";
    } else {
        note.textContent = "Every rule listed here was applied in the last analysis, including rules with zero matches.";
    }
    note.classList.toggle("stale", stale);
}

async function runAnalysis(sample = state.sample, file = state.custom, saved = state.saved) {
    if (state.busy) return;
    const revision = state.ruleRevision;
    state.busy = true;
    byId("run").disabled = true;
    message(state.live ? "Analysing the selected capture…" : "Loading fixture evidence…");
    try {
        let report;
        if (state.live) {
            let path = "/api/v1/analyze-pcap/" + sample;
            if (file) path = "/api/v1/upload" + (state.captureStorage ? "?name=" + encodeURIComponent(file.name) : "");
            if (saved) path = "/api/v1/captures/" + encodeURIComponent(saved.id) + "/analyze";
            const response = await fetch(path, {
                method: "POST", headers: file ? {"Content-Type": "application/octet-stream"} : {},
                body: file || null, signal: AbortSignal.timeout(190000)
            });
            const body = await response.json();
            if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : "Analysis failed.");
            report = body;
        } else {
            if (file || saved) throw new Error("Custom captures require a running analysis server.");
            report = demos[sample].report;
        }
        state.sample = sample;
        state.saved = report.saved_capture || saved;
        state.custom = state.saved ? null : file;
        if (report.saved_capture && !state.savedCaptures.some(capture => capture.id === report.saved_capture.id)) {
            state.savedCaptures.unshift(report.saved_capture);
            if (location.hash === "#captures") showPage();
        }
        state.report = report;
        state.reportRevision = revision;
        state.selected = report.findings.find(item => item.count)?.id || report.findings[0]?.id;
        renderResults();
        if (revision !== state.ruleRevision) message("Detection rules changed. Run analysis again to apply them to this capture.");
        else if (file && state.saved) message("Analysis complete · Capture saved to the library.");
        else message(report.engine === "Fixture replay" ? "Showing recorded evidence from the bundled fixture." : "Analysis complete · TShark inspected the capture.");
    } catch (error) {
        message("Analysis failed. " + error.message + " The previous result is still displayed.", true);
    } finally {
        byId("run").disabled = false;
        state.busy = false;
        const pending = state.pendingCapture;
        state.pendingCapture = null;
        if (pending) runAnalysis(pending.sample, pending.file, pending.saved);
    }
}

function openCapture(sample, file = null, saved = null) {
    location.hash = "workbench";
    if (state.busy) {
        state.pendingCapture = {sample, file, saved};
        message("Waiting to analyse the selected capture…");
    } else {
        runAnalysis(sample, file, saved);
    }
}

function savedCaptures(target) {
    if (!state.captureStorage && !state.captureLibraryError) return;
    const list = el("section", "library-section");
    list.append(el("h2", "", "Saved captures"));
    if (state.captureLibraryError) {
        list.append(el("p", "muted", state.captureLibraryError));
    } else if (!state.savedCaptures.length) {
        list.append(el("p", "muted", "Successfully analysed uploads will appear here."));
    }
    if (state.savedCaptures.length) {
        const cards = el("div", "catalog");
        for (const capture of state.savedCaptures) {
            const date = new Date(capture.uploaded_at);
            const size = capture.size >= 1024 ** 2 ?
                (capture.size / 1024 ** 2).toFixed(2) + " MiB" : (capture.size / 1024).toFixed(1) + " KiB";
            const card = el("article", "catalog-card");
            card.append(el("h3", "", capture.name), el("p", "", [size, date.toLocaleDateString()].join(" · ")));
            const actions = el("div", "actions");
            actions.append(button("Analyse saved capture", "secondary", () => openCapture("custom", null, capture)));
            card.append(actions);
            cards.append(card);
        }
        list.append(cards);
    }
    target.append(list);
}

async function requestCaptures() {
    try {
        const response = await fetch("/api/v1/captures", {signal: AbortSignal.timeout(5000)});
        if (!response.ok) throw new Error("Capture library unavailable");
        const library = await response.json();
        state.savedCaptures = library.captures;
        state.captureStorage = library.enabled;
    } catch {
        state.captureLibraryError = "The saved capture list could not be loaded. Refresh to reconnect to the library.";
    }
}

function captureLibrary(target) {
    const cards = el("div", "catalog");
    for (const [key, demo] of Object.entries(demos)) {
        const card = el("article", "catalog-card");
        card.append(el("div", "eyebrow", "Demo PCAP · " + demo.report.frames + " frames"),
            el("h2", "", demo.title), el("p", "", demo.description));
        const actions = el("div", "actions");
        actions.append(button("Analyse capture", "secondary", () => openCapture(key)));
        card.append(actions);
        cards.append(card);
    }
    const upload = el("section", "catalog-card upload");
    upload.append(el("h2", "", "Custom capture"));
    if (state.uploads) {
        const limit = (state.maxUploadBytes / 1024 ** 2) + " MiB";
        const input = el("input");
        input.type = "file";
        input.accept = ".pcap,.pcapng,.cap";
        input.setAttribute("aria-label", "Choose a packet capture");
        const feedback = el("p", "muted");
        feedback.setAttribute("role", "status");
        function analyseFile(file) {
            if (!file) return;
            if (file.size > state.maxUploadBytes) feedback.textContent = "Choose a capture no larger than " + limit + ".";
            else openCapture("custom", file);
        }
        input.addEventListener("change", () => analyseFile(input.files[0]));
        upload.addEventListener("dragover", event => { event.preventDefault(); upload.classList.add("dragging"); });
        upload.addEventListener("dragleave", () => upload.classList.remove("dragging"));
        upload.addEventListener("drop", event => {
            event.preventDefault();
            upload.classList.remove("dragging");
            analyseFile(event.dataTransfer.files[0]);
        });
        const handling = state.captureStorage ? "Successfully analysed files are saved to this library." : "The server deletes its temporary copy after analysis.";
        upload.append(el("p", "", "Choose or drop an authorised PCAP or PCAPNG, up to " + limit + " and 10,000 frames. " + handling), input, feedback);
    } else {
        upload.append(el("p", "", "This workspace accepts bundled captures. For custom uploads, install TShark and start the local server with ENABLE_UPLOADS=1, or run Docker Compose with ENABLE_UPLOADS=1."));
    }
    target.append(upload);
    savedCaptures(target);
    const samples = el("section", "library-section");
    samples.append(el("h2", "", "Bundled samples"), cards);
    target.append(samples);
}

async function requestRules(path = "", method = "GET", rule) {
    const response = await fetch("/api/v1/rules" + path, {
        method,
        headers: rule ? {"Content-Type": "application/json"} : {},
        body: rule ? JSON.stringify(rule) : undefined,
        signal: AbortSignal.timeout(15000)
    });
    const payload = await response.json();
    if (!response.ok) {
        const {detail} = payload;
        const validationMessage = Array.isArray(detail) && detail.map(item => {
            const field = item.loc.slice(1).join(".");
            return field ? field + " · " + item.msg : item.msg;
        }).join(" ");
        throw new Error(typeof detail === "string" ? detail : validationMessage || "The rules could not be loaded or saved.");
    }
    state.rules = payload.rules;
    state.rulesEditable = payload.editable;
}

async function mutateRule(id, method, rule, notice) {
    if (state.ruleSaving) throw new Error("Another rule change is in progress.");
    state.ruleSaving = true;
    try {
        await requestRules("/" + encodeURIComponent(id), method, rule);
        state.ruleRevision++;
        renderAppliedRules();
        state.ruleNotice = notice;
        message("Detection rules changed. Run analysis again to apply them to this capture.");
        if (location.hash === "#rules") {
            showPage();
            byId("add-rule")?.focus({preventScroll: true});
        }
    } finally {
        state.ruleSaving = false;
    }
}

function ruleField(container, name, labelText, value, options = {}) {
    const label = el("label", "rule-field", labelText);
    const field = el(options.choices ? "select" : options.rows ? "textarea" : "input");
    field.name = name;
    if (options.choices) {
        for (const choice of options.choices) field.append(el("option", "", choice));
    } else if (options.rows) {
        field.rows = options.rows;
    } else {
        field.type = options.type || "text";
    }
    field.value = value ?? "";
    if (options.required) field.required = true;
    if (options.readOnly) field.readOnly = true;
    if (options.pattern) field.pattern = options.pattern;
    if (options.step) field.step = options.step;
    if (options.placeholder) field.placeholder = options.placeholder;
    label.append(field);
    container.append(label);
    return field;
}

function ruleEditor(target, rule = {}, editing = false) {
    const panel = el("section", "catalog-card rule-editor");
    const title = el("h2", "", editing ? "Edit rule" : "Add a detection rule");
    title.id = "rule-editor-title";
    panel.setAttribute("aria-labelledby", title.id);
    const form = el("form");
    const fields = el("div", "rule-fields");
    const name = ruleField(fields, "name", "Rule name", rule.name, {required: true});
    ruleField(fields, "id", "Rule ID", rule.id, {
        required: true, readOnly: editing, pattern: "[A-Z0-9\\-]+", placeholder: "NET-SOC-104"
    });
    form.append(fields);
    ruleField(form, "filter", "Wireshark display filter", rule.filter, {
        required: true, rows: 3, placeholder: "ip && tcp.dstport == 443"
    });
    ruleField(form, "summary", "Description", rule.summary, {rows: 2});
    const classification = el("div", "rule-fields");
    ruleField(classification, "severity", "Severity", rule.severity || "Medium", {
        choices: ["Low", "Medium", "High", "Critical"]
    });
    ruleField(classification, "protocol", "Protocol label", rule.protocol || "TCP");
    ruleField(classification, "direction", "Direction", rule.direction || "ingress", {choices: ["ingress", "egress"]});
    form.append(classification);

    const advanced = el("details", "rule-advanced");
    advanced.append(el("summary", "", "Attack technique, controls and risk settings"));
    const mappings = el("div", "rule-fields");
    ruleField(mappings, "technique", "ATT&CK technique ID", rule.technique);
    ruleField(mappings, "technique_name", "ATT&CK technique name", rule.technique_name);
    ruleField(mappings, "tactic", "ATT&CK tactic", rule.tactic);
    advanced.append(mappings);
    ruleField(advanced, "controls", "ISO 27001 controls (ID | Name, one per line)",
        rule.controls?.map(control => control.join(" | ")).join("\n"), {rows: 3, placeholder: "A.8.16 | Monitoring activities"});
    ruleField(advanced, "playbook", "Containment steps (one per line)", rule.playbook?.join("\n"), {rows: 3});
    ruleField(advanced, "review", "Privacy review prompt", rule.review, {rows: 2});
    const risk = el("div", "rule-fields");
    ruleField(risk, "likelihood", "Likelihood (1–5)", rule.likelihood ?? 3, {type: "number", required: true});
    ruleField(risk, "impact", "Impact (1–5)", rule.impact ?? 3, {type: "number", required: true});
    ruleField(risk, "penalty", "Risk multiplier", rule.penalty ?? 1, {type: "number", step: "any", required: true});
    advanced.append(risk);
    const threshold = el("div", "rule-fields");
    ruleField(threshold, "min_connections", "Minimum distinct TCP connections", rule.min_connections, {type: "number"});
    ruleField(threshold, "window_seconds", "Connection window (seconds)", rule.window_seconds, {type: "number"});
    advanced.append(threshold);
    form.append(advanced);

    const feedback = el("p", "status");
    feedback.setAttribute("role", "status");
    const actions = el("div", "actions");
    const save = el("button", "primary", "Save rule");
    save.type = "submit";
    const cancel = button("Cancel", "secondary", () => {
        target.replaceChildren();
        byId("add-rule")?.focus({preventScroll: true});
    });
    actions.append(save, cancel);
    form.append(actions, feedback);
    panel.append(title, form);
    target.replaceChildren(panel);
    name.focus();

    form.addEventListener("submit", async event => {
        event.preventDefault();
        if (state.ruleSaving) return;
        feedback.classList.remove("error");
        try {
            const updated = Object.fromEntries(new FormData(form));
            for (const key of Object.keys(updated)) updated[key] = updated[key].trim();
            if (!editing && state.rules.some(item => item.id === updated.id)) {
                throw new Error("A rule already uses this ID. Choose another ID or edit the existing rule.");
            }
            updated.controls = updated.controls.split("\n").filter(line => line.trim()).map(line => {
                const pair = line.split("|").map(part => part.trim());
                if (pair.length !== 2 || !pair.every(Boolean)) throw new Error("Enter each control as ID | Name.");
                return pair;
            });
            updated.playbook = updated.playbook.split("\n").map(line => line.trim()).filter(Boolean);
            for (const key of ["likelihood", "impact", "penalty", "min_connections", "window_seconds"]) {
                if (updated[key]) updated[key] = Number(updated[key]);
                else delete updated[key];
            }
            if (editing && rule.short) updated.short = rule.short;
            save.disabled = true;
            cancel.disabled = true;
            feedback.textContent = "Saving rule…";
            await mutateRule(updated.id, "PUT", updated, editing ? "Rule updated." : "Rule added.");
        } catch (error) {
            feedback.textContent = error.message;
            feedback.classList.add("error");
        } finally {
            save.disabled = false;
            cancel.disabled = false;
        }
    });
}

function ruleCatalogue(target) {
    const cards = el("div", "rule-cards");
    const editor = el("div");
    if (state.rulesEditable) {
        const add = button("Add rule", "primary", () => ruleEditor(editor));
        add.id = "add-rule";
        target.append(add);
    }
    const status = el("p", "status", state.rulesError || state.ruleNotice);
    status.setAttribute("role", "status");
    status.classList.toggle("error", Boolean(state.rulesError));
    target.append(status, editor, cards);
    const rules = state.rules ?? Object.entries(demos).map(([sample, demo]) => {
        const finding = demo.report.findings.find(item => item.count);
        return {...finding, sample, summary: demo.description, controls: finding.risk.controls.map(control => [control.id, control.name])};
    });
    if (rules.length === 0) cards.append(el("p", "muted", "No detection rules are configured."));
    for (const rule of rules) {
        const card = el("article", "catalog-card");
        card.append(el("div", "eyebrow", rule.id + " · " + rule.severity), el("h2", "", rule.name));
        if (rule.summary) card.append(el("p", "", rule.summary));
        if (rule.filter) card.append(el("code", "rule-filter", rule.filter));
        const technique = [rule.technique, rule.technique_name].filter(Boolean).join(" · ");
        if (technique) card.append(el("p", "mono", technique));
        if (rule.controls.length) card.append(el("p", "", rule.controls.map(control => control.join(" ")).join(" · ")));
        const actions = el("div", "actions");
        if (rule.sample) actions.append(button("Inspect sample", "secondary", () => openCapture(rule.sample)));
        if (state.rulesEditable) {
            actions.append(button("Edit", "secondary", () => ruleEditor(editor, rule, true)),
                button("Delete", "secondary rule-delete", async event => {
                    if (state.ruleSaving || !window.confirm("Delete “" + rule.name + "”?")) return;
                    const remove = event.currentTarget;
                    remove.disabled = true;
                    status.classList.remove("error");
                    status.textContent = "Deleting rule…";
                    try {
                        await mutateRule(rule.id, "DELETE", undefined, "Rule deleted.");
                    } catch (error) {
                        status.textContent = error.message;
                        status.classList.add("error");
                    } finally {
                        remove.disabled = false;
                    }
                }));
        }
        if (actions.childElementCount) card.append(actions);
        cards.append(card);
    }
    if (state.rulesEditable && state.ruleDraft) {
        ruleEditor(editor, state.ruleDraft);
        state.ruleDraft = null;
    }
}

const pages = {
    workbench: ["Workbench", "Security workbench", "Investigate network detections and trace their impact on security controls."],
    captures: ["Capture library", "Capture library", "Upload a packet capture, revisit a saved capture or choose a bundled sample."],
    rules: ["Detection rules", "Detection rules", "Inspect the signatures, ATT&CK mappings and controls used by the workbench."]
};

function showPage() {
    const hash = location.hash.slice(1);
    const route = Object.hasOwn(pages, hash) ? hash : "workbench";
    const [crumb, title, description] = pages[route];
    document.title = title + " · SentinelGRC";
    byId("crumb").textContent = crumb;
    byId("page-title").textContent = title;
    byId("page-description").textContent = description;
    for (const a of document.querySelectorAll("[data-route]")) {
        if (a.dataset.route === route) a.setAttribute("aria-current", "page");
        else a.removeAttribute("aria-current");
    }
    byId("workbench").hidden = route !== "workbench";
    const target = byId("secondary-page");
    target.replaceChildren();
    target.hidden = route === "workbench";
    if (route === "captures") captureLibrary(target);
    if (route === "rules") ruleCatalogue(target);
}

async function start() {
    for (const node of document.querySelectorAll("[data-icon]")) node.append(icon(node.dataset.icon));
    for (const view of ["soc", "grc"]) byId(view + "-view").addEventListener("click", () => {
        state.view = view;
        renderResults();
    });
    byId("run").addEventListener("click", () => runAnalysis());
    window.addEventListener("hashchange", showPage);
    renderResults();
    showPage();
    if (location.protocol === "file:") {
        message("Offline demo · recorded evidence from the bundled fixture.");
        return;
    }
    try {
        const res = await fetch("/api/v1/config", {signal: AbortSignal.timeout(5000)});
        if (!res.ok) throw new Error("Configuration unavailable");
        const config = await res.json();
        state.live = true;
        const captureRequest = requestCaptures();
        const analysis = runAnalysis();
        await captureRequest;
        state.uploads = config.uploads;
        state.maxUploadBytes = config.max_upload_bytes;
        showPage();
        try {
            await requestRules();
        } catch {
            state.rulesError = "The rule catalogue could not be loaded. Showing bundled rule descriptions.";
        }
        if (location.hash === "#rules") showPage();
        else renderOverview(state.report);
        await analysis;
    } catch {
        message("Analysis service unavailable · showing bundled fixture evidence.", true);
    }
}

start();
