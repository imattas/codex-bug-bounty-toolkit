'use strict';

const $ = (selector) => document.querySelector(selector);
const state = { findings: [], csrf: '', selected: null, detailRequest: 0 };
const titles = { unreviewed: 'Unreviewed', reviewed: 'Reviewed', submitted: 'Submitted', fixed: 'Fixed', archived: 'Archived' };

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

async function api(url, options) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || 'Local dashboard request failed');
  return body;
}

function notice(text, error = false) {
  $('#notice').textContent = text;
  $('#notice').className = `notice${error ? ' error' : ''}${text ? '' : ' hidden'}`;
}

function filtered() {
  const query = $('#search').value.toLocaleLowerCase();
  return state.findings.filter(item =>
    (!$('#program').value || item.program === $('#program').value) &&
    (!$('#status').value || item.workflow.status === $('#status').value) &&
    `${item.title} ${item.program} ${item.reference} ${item.id}`.toLocaleLowerCase().includes(query));
}

function renderList() {
  const visible = filtered();
  $('#visible-count').textContent = `${visible.length} shown`;
  $('#nav-count').textContent = state.findings.length;
  $('#actionable-count').textContent = state.findings.filter(x => x.decision === 'actionable').length;
  $('#held-count').textContent = state.findings.filter(x => x.decision === 'held').length;
  $('#submitted-count').textContent = state.findings.filter(x => x.workflow.status === 'submitted').length;
  const list = $('#list');
  list.replaceChildren();
  if (!visible.length) {
    const empty = node('div', 'list-empty');
    empty.append(node('h2', '', state.findings.length ? 'No matching findings' : 'No findings yet'),
      node('p', '', state.findings.length ? 'Try another search or clear the filters.' : 'Add an engagement containing findings/<slug>/report.md or .bug-bounty/candidates notes, then refresh.'));
    list.append(empty);
    return;
  }
  for (const decision of ['actionable', 'held']) {
    const group = visible.filter(x => x.decision === decision);
    if (!group.length) continue;
    const heading = node('h2', 'group-heading', decision === 'actionable' ? 'Actionable' : 'Held for review');
    heading.append(node('span', '', group.length));
    list.append(heading);
    for (const item of group) {
      const button = node('button', `finding-card${state.selected === item.id ? ' selected' : ''}`);
      button.type = 'button';
      button.setAttribute('aria-label', item.title);
      button.setAttribute('aria-pressed', String(state.selected === item.id));
      const top = node('div', 'card-top');
      top.append(node('span', 'program-name', item.program), node('span', `workflow-tag ${item.workflow.status}`, titles[item.workflow.status]));
      button.append(top, node('span', 'card-title', item.title));
      const bottom = node('div', 'card-bottom');
      bottom.append(node('span', `decision-dot ${item.decision}`, item.kind === 'report' ? 'Report bundle' : 'Candidate notes'));
      bottom.append(node('span', 'score', item.score === null ? 'Unscored' : `CVSS ${item.score}`));
      button.append(bottom);
      button.addEventListener('click', () => select(item.id));
      button.addEventListener('keydown', event => {
        if (!['ArrowDown', 'ArrowUp'].includes(event.key)) return;
        event.preventDefault();
        const buttons = [...list.querySelectorAll('.finding-card')];
        buttons[(buttons.indexOf(button) + (event.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length].focus();
      });
      list.append(button);
    }
  }
}

function appendSection(parent, title) {
  const section = node('section', 'detail-section');
  section.append(node('h3', '', title));
  parent.append(section);
  return section;
}

// Deliberately small Markdown subset. All source text remains a text node;
// HTML, images, and links are never interpreted or fetched.
function renderReport(text) {
  const document = node('div', 'report-body');
  let paragraph = [];
  let list = null;
  let code = null;
  const flush = () => {
    if (paragraph.length) document.append(node('p', '', paragraph.join('\n')));
    paragraph = [];
    list = null;
  };
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*```/.test(line)) {
      flush();
      if (code) code = null;
      else {
        code = node('code');
        const block = node('pre');
        block.append(code);
        document.append(block);
      }
      continue;
    }
    if (code) {
      code.append(globalThis.document.createTextNode(line + '\n'));
      continue;
    }
    const heading = /^(#{1,4})\s+(.+)$/.exec(line);
    const numbered = /^\s*(\d+)\.\s+(.+)$/.exec(line);
    const bullet = /^\s*[-*]\s+(.+)$/.exec(line);
    if (heading) {
      flush();
      document.append(node(`h${Math.min(heading[1].length + 2, 6)}`, '', heading[2]));
    } else if (numbered || bullet) {
      if (paragraph.length) flush();
      const type = numbered ? 'OL' : 'UL';
      if (!list || list.tagName !== type) {
        list = node(type.toLowerCase());
        if (numbered) list.start = Number(numbered[1]);
        document.append(list);
      }
      list.append(node('li', '', numbered ? numbered[2] : bullet[1]));
    } else if (!line.trim()) flush();
    else {
      list = null;
      paragraph.push(line);
    }
  }
  flush();
  return document;
}

function renderDetail(item) {
  const detail = $('#detail');
  detail.replaceChildren();
  const header = node('header', 'detail-header');
  const top = node('div', 'detail-top');
  top.append(node('span', 'program-name', item.program), node('span', `gate-badge ${item.decision}`, item.decision === 'actionable' ? 'Actionable · recorded gates pass' : 'Held · review required'));
  header.append(top, node('h2', '', item.title), node('p', 'reference', item.reference));
  detail.append(header);
  const gates = appendSection(detail, 'Recorded triage');
  const gateGrid = node('div', 'gate-grid');
  for (const [key, name] of [['scope', 'Scope'], ['validation', 'Validation'], ['actionability', 'Impact'], ['duplicate', 'Duplicate check']]) {
    const field = node('div', 'gate-field');
    field.append(node('span', '', name), node('strong', '', (item.gate_statuses[key] || 'Not recorded').replaceAll('_', ' ')));
    gateGrid.append(field);
  }
  gates.append(gateGrid);
  if (item.gate_reasons.length) {
    const reasons = node('ul', 'gate-reasons');
    item.gate_reasons.forEach(reason => reasons.append(node('li', '', reason)));
    gates.append(reasons);
  }
  if (item.note) gates.append(node('p', 'candidate-note', item.note));
  if (item.kind === 'report') {
    const report = appendSection(detail, 'Report');
    report.append(renderReport(item.report));
  } else {
    gates.append(node('p', 'muted', 'Candidate record only. No report is generated by this viewer.'));
  }
  const artifacts = appendSection(detail, 'Supporting artifacts');
  if (!item.artifacts.length) artifacts.append(node('p', 'muted', 'No reviewed, hash-verified artifacts available.'));
  for (const artifact of item.artifacts) {
    const row = node('div', 'artifact-row');
    const description = node('div');
    description.append(node('span', 'artifact-name', artifact.name), node('span', 'artifact-meta', `${artifact.kind} · ${(artifact.size / 1024).toFixed(1)} KB`));
    const download = node('a', 'artifact-download', 'Download ↓');
    download.href = artifact.url;
    download.download = artifact.name;
    row.append(description, download);
    artifacts.append(row);
    if (artifact.image) {
      const image = node('img', 'evidence-image');
      image.alt = artifact.name;
      image.loading = 'lazy';
      image.src = `${artifact.url}?preview=1`;
      artifacts.append(image);
    } else if (/\.(txt|md|json|py|js|sh|ps1|html|svg|http|log|csv)$/i.test(artifact.name)) {
      const disclosure = node('details', 'artifact-preview');
      disclosure.append(node('summary', '', 'Preview as text'));
      disclosure.addEventListener('toggle', async () => {
        if (!disclosure.open || disclosure.dataset.loaded) return;
        disclosure.dataset.loaded = '1';
        const preview = node('pre', 'report-text', 'Loading preview…');
        disclosure.append(preview);
        try {
          const response = await fetch(artifact.url, { credentials: 'same-origin' });
          if (!response.ok) throw new Error('Artifact unavailable; refresh findings.');
          const text = await response.text();
          preview.textContent = text.slice(0, 32000) + (text.length > 32000 ? '\n[Preview truncated; download to read the full file.]' : '');
        } catch (error) { preview.textContent = error.message; }
      });
      artifacts.append(disclosure);
    }
  }
  const tracking = appendSection(detail, 'Manual tracking');
  tracking.append(node('p', 'muted', 'A local review log. Saving does not change gates or submit to any platform.'));
  const form = node('form', 'tracking-form');
  const statusLabel = node('label', '', 'Workflow status');
  const status = node('select');
  status.id = 'workflow';
  statusLabel.htmlFor = status.id;
  for (const [value, title] of Object.entries(titles)) {
    const option = node('option', '', title);
    option.value = value;
    status.append(option);
  }
  status.value = item.workflow.status;
  const notesLabel = node('label', '', 'Review notes');
  const notes = node('textarea');
  notes.id = 'notes';
  notesLabel.htmlFor = notes.id;
  notes.rows = 3;
  notes.maxLength = 4000;
  notes.placeholder = 'Decision context, next steps, or a submission reference…';
  notes.value = item.workflow.notes;
  const save = node('button', 'button primary', 'Save tracking');
  save.type = 'submit';
  const feedback = node('span', 'save-feedback');
  feedback.setAttribute('role', 'status');
  form.append(statusLabel, status, notesLabel, notes, save, feedback);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    save.disabled = true;
    feedback.textContent = 'Saving…';
    try {
      const result = await api(`/api/findings/${item.id}/state`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf }, body: JSON.stringify({ status: status.value, notes: notes.value }) });
      const current = state.findings.find(x => x.id === item.id);
      if (current) current.workflow = result.workflow;
      feedback.textContent = 'Tracking saved.';
      renderList();
    } catch (error) { feedback.textContent = error.message; }
    finally { save.disabled = false; }
  });
  tracking.append(form);
}

async function select(identifier) {
  state.selected = identifier;
  const request = ++state.detailRequest;
  renderList();
  $('#detail').replaceChildren(node('p', 'detail-loading', 'Loading finding…'));
  try {
    const item = await api(`/api/findings/${identifier}`);
    if (request === state.detailRequest) renderDetail(item);
  } catch (error) {
    if (request === state.detailRequest) $('#detail').replaceChildren(node('p', 'detail-loading error', error.message));
  }
}

async function refresh() {
  $('#refresh').disabled = true;
  notice('Loading local findings…');
  try {
    const result = await api('/api/findings');
    state.findings = result.findings;
    state.csrf = result.csrf_token;
    $('#root-name').textContent = result.root_name;
    const program = $('#program').value;
    $('#program').replaceChildren(node('option', '', 'All programs'));
    $('#program').firstChild.value = '';
    [...new Set(state.findings.map(x => x.program))].sort().forEach(name => {
      const option = node('option', '', name);
      option.value = name;
      $('#program').append(option);
    });
    if ([...$('#program').options].some(option => option.value === program)) $('#program').value = program;
    notice(result.truncated ? 'Discovery limit reached. Open a narrower engagement root to see all records.' : '');
    renderList();
    if (state.selected && state.findings.some(x => x.id === state.selected)) await select(state.selected);
    else if (state.findings.length) await select(state.findings[0].id);
    else {
      state.selected = null;
      $('#detail').replaceChildren(node('p', 'detail-loading', 'Select a finding after adding engagement records.'));
    }
  } catch (error) { notice(`${error.message}. Check the local server and try Refresh.`, true); }
  finally { $('#refresh').disabled = false; }
}

$('#refresh').addEventListener('click', refresh);
for (const selector of ['#search', '#program', '#status']) $(selector).addEventListener('input', renderList);
document.addEventListener('keydown', event => {
  if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
    event.preventDefault();
    $('#search').focus();
  }
});
refresh();
