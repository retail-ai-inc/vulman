import { Call } from '/wails/runtime.js';
const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
const esc = v => String(v ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const icons = {
  overview:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  projects:'<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/>',
  vulnerabilities:'<path d="M12 3 3 7v6c0 5 9 9 9 9s9-4 9-9V7Z"/><path d="M12 8v5m0 4h.01"/>',
  activity:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  settings:'<path d="m9 3-1 3-3 1 1 3-2 2 2 2-1 3 3 1 1 3h6l1-3 3-1-1-3 2-2-2-2 1-3-3-1-1-3Z"/><circle cx="12" cy="12" r="3"/>',
  refresh:'<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1"/>',
  edit:'<path d="M4 20l1-5L16 4a2.8 2.8 0 0 1 4 4L9 19l-5 1Zm10-14 4 4"/>',
  scanCode:'<path d="m5 4-3.5 3.5L5 11m4.5-7L13 7.5 9.5 11"/><circle cx="15.5" cy="15.5" r="4.5"/><path d="m19 19 3 3"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  search:'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  stack:'<path d="m12 3 10 5-10 5L2 8Zm-9 10 9 5 9-5M3 18l9 5 9-5"/>',
  leaf:'<path d="M20 3C6 1 2 8 5 15s16 6 15-12Z"/><path d="M4 22 15 9M9 17V9"/>',
  eye:'<path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z"/><circle cx="12" cy="12" r="2.5"/>',
  eyeOff:'<path d="M3 3l18 18M9 6.5a10 10 0 0 1 3-.5c6.5 0 10 6 10 6a15 15 0 0 1-3 3.4M15 17.5a10 10 0 0 1-3 .5c-6.5 0-10-6-10-6a15 15 0 0 1 3-3.4"/>'
};
const icon = n => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[n]||icons.stack}</svg>`;
let componentDraft = null;

async function confirmAction(message) {
  const dialog = $('#confirm-dialog');
  $('#confirm-message').textContent = message;
  dialog.returnValue = '';
  return new Promise(resolve => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), {once:true});
    dialog.showModal();
  });
}

const defaultLanguage = 'en';
let localizations = {};
let state, lang=defaultLanguage, toastTimer, currentFinding, clearing=new Set();
const syncSelection = {};
const syncModeSelection = {};
const syncSeveritySelection = {};
const componentSyncSeveritySelection = new Map();
let syncAllSeverity='';
let pendingPageRender = 0;
let pollPending = false;
let changingDataDirectory = false;
const githubTokenSettingsHash = '#settings/github';
const newProjectHash = '#projects/new';
let newProjectReturnHash = '';
let projectTokenSetup = null;
let projectDeleteDraft = null;
const findingsPerPage = 100;
const findingSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
let findingsPage = 1;
let filter={search:'',severity:'',project:'',match:'',stack:''}, projectTab='vulnerabilities';
const t = key => localizations[lang]?.messages[key] || localizations[defaultLanguage]?.messages[key] || key;
const supportedLanguage = code => Object.hasOwn(localizations, code) ? code : defaultLanguage;
const formatLocale = () => localizations[lang]?.locale || lang;
function languageOptions() {
  return Object.entries(localizations).map(([code, localization]) => {
    const value = esc(code);
    return `<option value="${value}" lang="${value}" ${code === lang ? 'selected' : ''}>${esc(localization.name)}</option>`;
  }).join('');
}
const fmtDate = d => !d || d.startsWith('0001') ? '—' : new Date(d).toLocaleString(formatLocale(),{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
const validDate = d => d && !d.startsWith('0001');
const severityKey = v => ({CRITICAL:'critical',HIGH:'high',MEDIUM:'medium',LOW:'low',UNKNOWN:'unknown'})[v] || 'unknown';
const pill = (text,cls='') => `<span class="pill ${esc(cls)}">${esc(text)}</span>`;
const button = (label,action,primary=false,ico='') => `<button class="button ${primary?'primary':'secondary'}" data-action="${action}">${ico?icon(ico):''}${esc(t(label))}</button>`;
const allRuns = () => state.projects.flatMap(p=>(p.runs||[]).map(r=>({...r,project_id:p.id,project_name:p.name}))).sort((a,b)=>b.started_at.localeCompare(a.started_at));
const route = () => location.hash.slice(1).split('/');
const safeURL = u => {try {const x=new URL(u);return ['https:','http:'].includes(x.protocol)?esc(x.href):'';}catch{return '';}};
function invoke(method, ...args) {
  return Call.ByName('main.Desktop.' + method, ...args);
}
function toast(message,error=false,kind=''){clearTimeout(toastTimer);const el=$('#toast');el.textContent=message;el.className='toast'+(error?' error':'')+(kind==='connection-lost'?' connection-lost':'');el.hidden=false;toastTimer=setTimeout(()=>el.hidden=true,6000);}
function localize(root=document){$$('[data-t]',root).forEach(el=>el.textContent=t(el.dataset.t));document.documentElement.lang=lang;const languageSelect=$('#language-select');languageSelect.value=lang;languageSelect.setAttribute('aria-label',t('uiLanguage'));}
async function refresh(renderPage=true){state=await invoke('State');lang=supportedLanguage(state.settings.language);localize();if(renderPage)render();}
function renderNav(){const active=route()[0]||'overview';const findingCount=state.projects.reduce((total,p)=>total+(p.findings?.length||0),0);$('#nav').innerHTML=['overview','projects','vulnerabilities','activity','settings'].map(n=>`${n==='settings'?'<div class="nav-separator"></div>':''}<a class="nav-link ${active===n||(active==='project'&&n==='projects')?'active':''}" href="#${n}">${icon(n)}<span>${t(n)}</span>${n==='projects'?`<span class="nav-count">${state.projects.length}</span>`:n==='vulnerabilities'&&findingCount?`<span class="nav-count">${findingCount}</span>`:''}</a>`).join('');$('#breadcrumb-page').textContent=t(active==='project'?'projects':active);}
function heading(title,sub='',actions='',eyebrow=''){return `<div class="page-heading"><div>${eyebrow?`<div class="eyebrow">${esc(eyebrow)}</div>`:''}<h1>${esc(title)}</h1>${sub?`<p class="subtitle">${esc(sub)}</p>`:''}</div><div class="heading-actions">${actions}</div></div>`;}
function empty(title,sub,art='projects',actions=''){return `<div class="empty-state"><div class="empty-art">${icon(art)}</div><h3>${t(title)}</h3><p>${t(sub)}</p>${actions}</div>`;}
const expandedRuns=new Set();
const dismissedRuns=new Set();
function canDismissWorkflow(run){return !!run&&['complete','partial','failed','interrupted','stopped'].includes(run.status);}
function stepLabel(step){return ({nvd:'NIST NVD',osv:'OSV.dev',cve:'CVE Program',scanner:t('codeScanners'),save:t('saveResults')}[step.kind]||step.kind)+(step.component?' · '+step.component:'');}
function interruptionMessage(run, fullProject = false) {
  const step = run.steps?.find(step => step.status === 'interrupted');
  const key = fullProject ? 'fullSyncInterrupted' : 'syncInterrupted';
  return step ? t(key + 'During').replace('{step}', () => stepLabel(step)) : t(key);
}
function scanTargetLabel(target, repository) {
  return repository || (target ? t('scanTarget_' + target) : '');
}

function findingVersionLabel(finding) {
  return [finding.version, scanTargetLabel(finding.scan_target, finding.scan_repository)].filter(Boolean).join(' · ');
}

function projectRepositories(project) {
  return project?.repository_urls ?? (project?.repository ? [project.repository] : []);
}

function projectRepositoryLinks(project) {
  const links = projectRepositories(project).map(safeURL).filter(Boolean);
  return links.map((href, i) => {
    const label = t('repositoryLink') + (links.length > 1 ? ' ' + (i + 1) : '');
    return `<a class="pill" href="${href}" title="${href}" target="_blank" rel="noreferrer">${esc(label)} ↗</a>`;
  }).join('');
}

function workflowLogs(run, steps) {
  const entries = (run.logs || []).slice().reverse();
  if (!entries.some(entry => entry.step_id === 'scanner')) {
    if (run.asset_id) entries.unshift({step_id:'scanner', event:'scanner_skipped_component'});
    else if (run.mode === 'local') entries.unshift({step_id:'scanner', event:'scanner_skipped_cache'});
    else if (canDismissWorkflow(run) && !steps.some(step => step.kind === 'scanner')) entries.unshift({step_id:'scanner', event:'scanner_unrecorded'});
  }
  return entries.map(entry => {
    const step = steps.find(step => step.id === entry.step_id);
    const scanner = entry.step_id === 'scanner';
    const source = scanner ? t('codeScanners') : step && stepLabel(step);
    let event = entry.event;
    let detail = event === 'run_finished' ? t(entry.detail) : entry.detail;
    if (scanner && event === 'scanner_configured') {
      if (detail) detail = detail.split(',').map(name => scannerLabels[name] || name).join(', ');
      else event = 'scanner_none_configured';
    } else if (scanner && event === 'skipped' && run.mode === 'local') {
      event = 'scanner_skipped_cache';
    } else if (scanner && event === 'scanner_missing_token') {
      detail = '';
    } else if (scanner && detail) {
      const [name, ...rest] = detail.split(' · ');
      detail = [scannerLabels[name] || name, ...rest].join(' · ');
    }
    const parts = [source, scanTargetLabel(entry.scan_target, entry.scan_repository), t('event_' + event), detail];
    if (Number.isInteger(entry.findings)) {
      const key = entry.findings === 1 ? 'scannerFindingReported' : 'scannerFindingsReported';
      parts.push(t(key).replace('{count}', entry.findings.toLocaleString(formatLocale())));
    }
    const cleanup = event === 'scanner_cleanup_completed' || event === 'scanner_cleanup_failed';
    const error = ['failed', 'interrupted', 'scanner_failed', 'scanner_interrupted', 'scanner_target_failed', 'scanner_cleanup_failed'].includes(event);
    const time = entry.at ? `<time>${esc(new Date(entry.at).toLocaleTimeString(formatLocale(),{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}))}</time>` : '<time>—</time>';
    const text = esc(parts.filter(Boolean).join(' · '));
    return `<li class="${error ? 'workflow-log-error' : ''}">${time}<span>${cleanup ? `<strong>${text}</strong>` : text}</span></li>`;
  }).join('');
}
function workflowElapsed(run){const end=validDate(run.finished_at)?new Date(run.finished_at).getTime():validDate(run.paused_at)?new Date(run.paused_at).getTime():Date.now();const seconds=Math.max(0,Math.floor((end-new Date(run.started_at).getTime())/1000-(run.paused_seconds||0))||0);return Math.floor(seconds/60)+'m '+seconds%60+'s';}
function stepProgress(step) {
  const progress = step.progress || {};
  const scanner = step.kind === 'scanner';
  const running = step.status === 'running';
  if (scanner && step.status === 'skipped' && progress.phase?.startsWith('scanner_skipped_')) {
    return t('event_' + progress.phase);
  }

  const parts = [];
  if (running) parts.push(t('phase_' + (progress.phase || 'request')));
  if (progress.item && (!scanner || running || ['interrupted', 'stopped'].includes(step.status))) {
    if (scanner && progress.scan_target) parts.push(scanTargetLabel(progress.scan_target, progress.scan_repository));
    parts.push(scanner ? scannerLabels[progress.item] || progress.item : progress.item);
  }
  if (progress.wait_seconds && running && progress.phase === 'waiting') parts.push(progress.wait_seconds + 's');
  if (progress.total > 0) parts.push(progress.processed + ' / ' + progress.total + ' ' + t('processed'));
  else if (progress.processed > 0) parts.push(progress.processed + ' ' + t('processed'));
  if (step.status === 'complete' || progress.found > 0) {
    const count = progress.found || 0;
    if (scanner) {
      parts.push(t(count === 1 ? 'scannerFindingBeforeMerge' : 'scannerFindingsBeforeMerge').replace('{count}', formatResultNumber(count)));
    } else if (step.kind === 'save' && step.status === 'complete') {
      parts.push(t(count === 1 ? 'uniqueFindingSaved' : 'uniqueFindingsSaved').replace('{count}', formatResultNumber(count)));
    } else {
      parts.push(count + ' ' + t(step.kind === 'cve' ? 'records' : 'findings'));
    }
  }
  if (progress.cache_status) parts.push(t('cache_' + progress.cache_status));
  if (validDate(progress.checked_at)) parts.push(t('sourceDataChecked') + ' ' + fmtDate(progress.checked_at));
  return parts.join(' · ');
}
function workflowControls(project,run){if(!['running','pausing','paused','stopping'].includes(run.status))return '';const control=(action,label,danger=false)=>`<button type="button" class="button ${danger?'danger':'secondary'} small" data-action="control-sync" data-control="${action}" data-id="${esc(project.id)}" data-run="${esc(run.id)}" ${run.status==='stopping'?'disabled':''}>${t(label)}</button>`;return (run.status==='stopping'?'':control(run.status==='running'?'pause':'resume',run.status==='running'?'pauseSync':'resumeSync'))+control('stop','stopSync',true);}
async function controlWorkflow(projectID,runID,action){if(action==='stop'&&!(await confirmAction(t('confirmStopSync'))))return false;await invoke('ControlRun',projectID,runID,action);await refresh();toast(t('control_'+action));return true;}
function codeScanSeverityBreakdown(project, run) {
  if (run.mode !== 'code' || run.status !== 'complete') return '';
  let counts = run.severity_counts;
  let heading = 'severityBreakdown';
  if (!counts && run.count === 0) counts = {};
  if (!counts && project.runs?.[0]?.id === run.id && Array.isArray(project.findings)) {
    const saved = {};
    let total = 0;
    for (const finding of project.findings) {
      if (finding.match !== 'scanner') continue;
      const severity = findingSeverities.includes(finding.severity) ? finding.severity : 'UNKNOWN';
      saved[severity] = (saved[severity] || 0) + 1;
      total++;
    }
    if (total === run.count) {
      counts = saved;
      heading = 'savedCodeSeverityBreakdown';
    }
  }
  if (!counts) return `<p class="workflow-severity">${esc(t('severityBreakdownUnavailable'))}</p>`;
  return `<div class="workflow-severity"><span>${esc(t(heading))}</span>${severityCountList(counts)}</div>`;
}

function severityCountList(counts) {
  const items = findingSeverities.map(severity => {
    const key = severityKey(severity);
    return `<li class="pill ${key}">${esc(t(key))} <strong>${formatResultNumber(counts[severity] ?? 0)}</strong></li>`;
  }).join('');
  return `<ul class="severity-counts">${items}</ul>`;
}

function workflowBody(project,run,dismissible=false){
  const steps=run.steps||[],done=steps.filter(s=>!['pending','running'].includes(s.status)).length;
  const current=steps.find(s=>s.status==='running')||(run.status==='running'?steps.find(s=>s.status==='pending'):null);
  const expanded=expandedRuns.has(run.id),detailsID='workflow-details-'+run.id;
  const statusMessage = {pausing:'pauseHint', paused:'pausedHint', stopping:'stoppingHint', partial:'assessmentPartial'}[run.status];
  const summary = run.status === 'interrupted' ? interruptionMessage(run) : statusMessage && t(statusMessage);
  const codeScan = run.mode === 'code';
  const scope = codeScan ? syncSeverityLabel(run.severity) : `${run.asset_name || t('syncEverything')} · ${syncSeverityLabel(run.severity)} · ${t('mode_' + (run.mode || 'auto'))}`;
  const progress=t('stepsFinished').replace('{done}',done).replace('{total}',steps.length);
  return `<div class="workflow-heading"><div><h3>${t(codeScan ? 'codeScanWorkflow' : 'workflow')} · ${esc(project.name)}</h3><p>${esc(scope)} · ${t('elapsed')} ${workflowElapsed(run)}</p>${validDate(run.data_checked_at)?`<p title="${t('sourceDataHint')}">${t('sourceDataChecked')}: ${fmtDate(run.data_checked_at)}</p>`:''}</div><div class="workflow-actions">${pill(t(run.status),run.status)}${workflowControls(project,run)}<button type="button" class="button secondary small" data-toggle-workflow="${esc(run.id)}" aria-expanded="${expanded}" aria-controls="${esc(detailsID)}">${t(expanded?'showLess':'showMore')}</button>${dismissible&&canDismissWorkflow(run)?`<button type="button" class="icon-button workflow-close" data-dismiss-workflow="${esc(run.id)}" data-project-id="${esc(project.id)}" aria-label="${t('closeWorkflow')}" title="${t('closeWorkflow')}">×</button>`:''}</div></div><div class="workflow-progress"><progress max="${Math.max(1,steps.length)}" value="${done}" aria-label="${esc(progress)}"></progress><span>${esc(progress)}</span></div><div class="workflow-current" role="status">${summary?esc(summary):current?`${esc(stepLabel(current))}<span>${esc(stepProgress(current)||t('phase_queued'))}</span>`:esc(t(run.status==='running'?'finishing':run.status))}</div>${codeScanSeverityBreakdown(project, run)}<div class="workflow-details" id="${esc(detailsID)}" ${expanded?'':'hidden'}>${expanded?`<ol class="workflow-stepper">${steps.map(step=>`<li class="workflow-step ${esc(step.status)}"><span class="workflow-step-marker" aria-hidden="true">${{complete:'✓',running:'↻',failed:'!',interrupted:'!',stopped:'■',skipped:'–',pending:'·'}[step.status]||'·'}</span><div><strong>${esc(stepLabel(step))}</strong><p>${esc(stepProgress(step))}</p></div>${pill(t(step.status),step.status)}</li>`).join('')}</ol><div class="workflow-log-heading"><h3>${t('workflowLogs')}</h3><small>${t('workflowLogsHint')}</small></div><ol class="workflow-logs" tabindex="0" aria-label="${esc(t('workflowLogs'))}">${workflowLogs(run, steps)}</ol>`:''}</div>`;
}
function workflowRun(project,run,dismissible=false){if(dismissible&&canDismissWorkflow(run)&&dismissedRuns.has(run.id))return '';return run?.steps?.length?`<section class="sync-workflow ${esc(run.status)}" data-sync-project-id="${esc(project.id)}" data-sync-run="${esc(run.id)}" data-sync-scope="${run.asset_id || run.severity || run.mode === 'code' ? 'scoped' : 'full'}" data-workflow-dismissible="${dismissible}">${workflowBody(project,run,dismissible)}</section>`:'';}
function mountActiveSyncs(){if(['project','settings','activity'].includes(route()[0]))return;const html=state.projects.filter(p=>p.syncing).map(p=>workflowRun(p,p.runs?.[0])).join('');$('.page-heading')?.insertAdjacentHTML('afterend','<div id="active-syncs">'+html+'</div>');}
function updateSyncPanels(runID){
  for (const el of $$('[data-sync-run]')) {
    if (runID && el.dataset.syncRun !== runID) continue;
    const project = state.projects.find(p => p.id === el.dataset.syncProjectId);
    const run = project?.runs?.find(r => r.id === el.dataset.syncRun);
    if (!run) continue;
    const dismissible = el.dataset.workflowDismissible === 'true';
    if (dismissible && canDismissWorkflow(run) && dismissedRuns.has(run.id)) {
      el.remove();
      continue;
    }
    // Replacing paused or finished panels during polling restarts their animations.
    if (runID || (run.status !== 'paused' && !canDismissWorkflow(run))) {
      const logs = $('.workflow-logs', el);
      const scrollTop = logs?.scrollTop;
      const focused = logs && document.activeElement === logs;
      el.innerHTML = workflowBody(project, run, dismissible);
      if (logs) {
        const updated = $('.workflow-logs', el);
        if (updated) {
          updated.scrollTop = scrollTop;
          if (focused) updated.focus({preventScroll:true});
        }
      }
    }
  }
}
function dismissWorkflow(projectID,runID){const project=state.projects.find(p=>p.id===projectID),run=project?.runs?.find(r=>r.id===runID);if(!canDismissWorkflow(run))return false;dismissedRuns.add(runID);$$('[data-sync-run]').forEach(el=>{if(el.dataset.workflowDismissible==='true'&&el.dataset.syncProjectId===projectID&&el.dataset.syncRun===runID)el.remove();});return true;}
function toggleWorkflow(id) {
  if (expandedRuns.has(id)) expandedRuns.delete(id);
  else expandedRuns.add(id);
  updateSyncPanels(id);
}
function progressSnapshot(st){const {cache_stats,version,...rest}=st;return JSON.stringify({...rest,projects:st.projects.map(p=>({...p,runs:(p.runs||[]).map(({steps,logs,data_checked_at,...run})=>run)}))});}
function applyPollingState(next) {
  const [page, id, view] = route();
  if (next.projects === undefined) {
    state.cache_stats = next.cache_stats;
    if (page === 'settings') updateCacheMetrics(next.cache_stats);
    else updateSyncPanels();
    return;
  }
  if (page === 'settings') {
    state = {...next, settings:state.settings};
    updateCacheMetrics(next.cache_stats);
    return;
  }
  if ((page === 'project' && view === 'edit') || location.hash === newProjectHash) {
    state = next;
    return;
  }
  if (page === 'project' && view === 'delete') {
    state = next;
    renderProjectDeletion(id);
    return;
  }
  const progressOnly = progressSnapshot(next) === progressSnapshot(state);
  state = next;
  lang = supportedLanguage(state.settings.language);
  if (progressOnly) updateSyncPanels();
  else {
    localize();
    render();
  }
}
function latestFullRun(p){return p.runs?.find(r=>!r.asset_id&&!r.severity&&r.mode!=='code');}
function projectStatus(p){const full=latestFullRun(p);if(p.syncing){const status=p.runs?.[0]?.status;return ['pausing','paused','stopping'].includes(status)?pill(t(status),status):pill(t(p.runs?.[0]?.mode==='code'?'scanningCode':'syncing'),'running pulse');}if(full&&full.status!=='complete')return pill(t(full.status),full.status);if(p.revision!==p.assessed_revision&&p.assessed_revision)return pill(t('stale'),'review');if(!validDate(p.last_sync))return pill(t('fullAssessmentNeeded'));return pill(t('complete'));}
function syncSeverityLabel(severity){return severity?t(severityKey(severity)):t('anySeverity');}
function severityOptions(selected=''){return `<option value="">${t('anySeverity')}</option>`+findingSeverities.map(value=>`<option value="${value}" ${selected===value?'selected':''}>${syncSeverityLabel(value)}</option>`).join('');}
function syncAllControls(primary=false){return `<div class="sync-all-controls"><label class="sync-scope sync-severity"><span>${t('syncSeverity')}</span><select id="sync-all-severity" data-sync-all-severity aria-label="${t('syncSeverity')}" title="${t('severitySyncHint')}">${severityOptions(syncAllSeverity)}</select></label>${button('syncAll','sync-all',primary,'refresh')}</div>`;}
function syncControls(p){const selected=p.assets.some(a=>a.id===syncSelection[p.id])?syncSelection[p.id]:'';return `<div class="sync-controls"><label class="sync-scope"><span>${t('syncScope')}</span><select id="sync-asset" data-sync-project="${p.id}" aria-label="${t('syncScope')}" ${p.syncing?'disabled':''}><option value="">${t('syncEverything')}</option>${p.assets.map(a=>`<option value="${esc(a.id)}" ${selected===a.id?'selected':''}>${esc(t(a.kind)+' · '+a.name+' '+a.version)}</option>`).join('')}</select></label><label class="sync-scope sync-severity"><span>${t('syncSeverity')}</span><select id="sync-severity" data-sync-severity-project="${p.id}" aria-label="${t('syncSeverity')}" title="${t('severitySyncHint')}" ${p.syncing?'disabled':''}>${severityOptions(syncSeveritySelection[p.id]||'')}</select></label><label class="sync-scope sync-mode"><span>${t('syncMode')}</span><select id="sync-mode" data-sync-mode-project="${p.id}" aria-label="${t('syncMode')}" ${p.syncing?'disabled':''}>${['auto','local','refresh'].map(mode=>`<option value="${mode}" ${(syncModeSelection[p.id]||'auto')===mode?'selected':''}>${t('mode_'+mode)}</option>`).join('')}</select></label><button class="button primary" data-action="sync" data-id="${p.id}" ${p.syncing?'disabled':''}>${icon('refresh')}${t(p.syncing&&p.runs?.[0]?.mode!=='code'?'syncing':'sync')}</button></div>`;}

function projectList(projects = state.projects, showEdit = false) {
  if (!projects.length) return empty('noProjects','noProjectsSub','projects',button('firstProject','new-project',true,'plus')+`<button class="sample-button" data-action="sample">${t('sample')}</button>`);
  return projects.map(project => {
    const id = esc(project.id);
    const components = `${formatResultNumber(project.assets?.length ?? 0)} ${t('components')}`;
    const description = esc(project.description);
    const details = projectListSummary(project, components) + (description ? `<p>${description}</p>` : '');
    const card = `<a class="project-card" href="#project/${id}"><div class="project-avatar">${esc(project.name.slice(0, 2).toUpperCase())}</div><div class="project-info"><strong>${esc(project.name)}</strong>${details}</div><div class="project-card-stats">${projectStatus(project)}</div><span class="chevron">›</span></a>`;
    if (!showEdit) return card;
    return `<div class="project-list-row">${card}<button type="button" class="button secondary small project-list-edit" data-action="edit-project" data-id="${id}" aria-label="${esc(t('editProject') + ' · ' + project.name)}" ${project.syncing ? 'disabled' : ''}>${t('editProject')}</button></div>`;
  }).join('');
}

function projectListSummary(project, components) {
  const repositoryCount = projectRepositories(project).length;
  const repositories = repositoryCount
    ? `<span>${esc(t(repositoryCount === 1 ? 'projectRepositoryCountOne' : 'projectRepositoryCount').replace('{count}', formatResultNumber(repositoryCount)))}</span>`
    : '';
  let critical = 0;
  for (const finding of project.findings || []) {
    if (finding.severity === 'CRITICAL') critical++;
  }
  return `<p class="project-list-summary"><span>${components}</span>${repositories}${pill(t('critical') + ' ' + formatResultNumber(critical), critical ? 'critical' : '')}</p>`;
}
function sourcesPanel(){return `<div class="panel sources-panel"><div class="panel-head"><div><h2>${t('dataSources')}</h2><p>${t('sourcesSub')}</p></div>${icon('stack')}</div>${[['nvd','NVD','discovery'],['cve','CVE','enrichment'],['osv','OSV','packageMatching']].map(([id,name,note])=>`<div class="source-item"><span class="source-symbol">${name}</span><div><strong>${name==='NVD'?'NIST NVD':name==='CVE'?'CVE Program':'OSV.dev'}</strong><small>${t(note)} · ${t(state.settings.sources[id]?'enabled':'disabled')}</small></div><span class="status-dot ${state.settings.sources[id]?'':'off'}"></span></div>`).join('')}<p class="source-note">${t('sourceNote')}</p></div>`;}
function breakdown(counts) {
  const max = Math.max(1, ...findingSeverities.map(severity => counts[severity] || 0));
  const colors = ['#c87a68','#d4a166','#cfbd70','#9bb47d','#b6c2aa'];
  const rows = findingSeverities.map((severity, index) => {
    const count = counts[severity] || 0;
    return `<a class="severity-row" href="#vulnerabilities/${severity}"><span class="severity-label">${t(severityKey(severity))}</span><svg viewBox="0 0 100 5" preserveAspectRatio="none" aria-hidden="true"><rect width="${count / max * 100}" height="5" rx="2" fill="${colors[index]}"/></svg><strong>${count}</strong></a>`;
  }).join('');
  return `<div class="panel"><div class="panel-head"><h2>${t('severityBreakdown')}</h2></div><div class="severity-chart">${rows}</div></div>`;
}
function canDeleteActivity(run){return !!run&&['interrupted','partial','failed','stopped'].includes(run.status);}
async function deleteActivity(projectID,runID){const p=state.projects.find(p=>p.id===projectID),run=p?.runs?.find(r=>r.id===runID);if(!canDeleteActivity(run))return false;if(!(await confirmAction(t('confirmDeleteActivity')+'\n\n'+p.name+' · '+fmtDate(run.started_at))))return false;await invoke('DeleteRun',projectID,runID);expandedRuns.delete(runID);dismissedRuns.delete(runID);await refresh();toast(t('activityDeleted'));return true;}
function activityList(runs=allRuns(),compact=false){if(!runs.length)return empty('noActivity','noActivitySub','activity');return runs.map(r=>`<div class="activity-item"><span class="activity-symbol">${r.status==='complete'?'✓':r.status==='running'?'↻':['pausing','paused'].includes(r.status)?'Ⅱ':['stopping','stopped'].includes(r.status)?'■':'!'}</span><div class="activity-content"><strong><a href="#project/${r.project_id}">${esc(r.project_name)}</a> · ${t(r.mode==='code'?'codeScan':'assessment')}</strong><p>${t(r.trigger==='schedule'?'scheduled':'manual')} · ${r.mode==='code'?'':esc(r.asset_id?r.asset_name:t('syncEverything'))+' · '} ${syncSeverityLabel(r.severity)} · ${t(r.status)} · ${r.count} ${t('findings')}</p>${workflowRun({id:r.project_id,name:r.project_name},r)}${r.warnings?.length?`<details><summary>${t('warnings')} (${r.warnings.length})</summary><ul>${r.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul></details>`:''}</div><div class="activity-actions"><span class="activity-time">${fmtDate(r.started_at)}</span>${canDeleteActivity(r)?`<button type="button" class="button danger small" data-action="delete-activity" data-id="${esc(r.project_id)}" data-run="${esc(r.id)}">${t('deleteActivity')}</button>`:''}</div></div>`).join('');}
function renderOverview(){
  const counts = Object.create(null);
  let total = 0, assets = 0;
  for (const project of state.projects) {
    assets += project.assets.length;
    for (const {severity} of project.findings || []) {
      total++;
      counts[severity] = (counts[severity] || 0) + 1;
    }
  }
  $('#main').innerHTML=heading(t('securityOverview'),t('overviewSub'),(state.projects.length?syncAllControls(false):'')+button('addProject','new-project',true,'plus'),'VULNERABILITY MANAGEMENT')+`<div class="metrics">${[['totalFindings',total,'allSeverities','vulnerabilities',''],['critical',counts.CRITICAL||0,'criticalNote','vulnerabilities','critical-text'],['high',counts.HIGH||0,'highNote','activity','high-text'],['projectCount',state.projects.length,'components','projects','']].map(([key,value,note,ico,cls])=>`<div class="metric"><div class="metric-top"><span>${t(key)}</span>${icon(ico)}</div><div class="metric-value ${cls}">${value}</div><div class="metric-note ${cls}">${cls?'<span class="dot"></span>':''}${key==='projectCount'?assets+' ':''}${t(note)}</div></div>`).join('')}</div><div class="dashboard-grid"><div><div class="panel"><div class="panel-head"><div><h2>${t('yourProjects')}</h2><p>${t('projectPanelSub')}</p></div><a class="text-link" href="#projects">${t('viewAll')} ↗</a></div>${projectList(state.projects.slice(0,5))}<div class="panel-bottom">${icon('check')}${t('localInventory')}</div></div><div class="section-caption"><h2>${t('recentActivity')}</h2><a class="text-link" href="#activity">${t('viewAll')} ↗</a></div><div class="panel">${activityList(allRuns().slice(0,3),true)}</div></div><aside class="dashboard-aside">${sourcesPanel()}${total?breakdown(counts):`<div class="insight">${icon('leaf')}<div class="eyebrow">${t('schedule').toUpperCase()}</div><h3>${t('quietTitle')}</h3><p>${t('quietText')}</p></div>`}</aside></div>`;}
function stackKey(projectID,assetID){return JSON.stringify([projectID,assetID]);}
function scanLocationKey(projectID, target) {
  return JSON.stringify([projectID, 'scanner', target]);
}
function scanLocations(project) {
  const repositories = state.scan_repositories?.[project.id] || [];
  const labelCounts = new Map();
  for (const {label} of repositories) labelCounts.set(label, (labelCounts.get(label) || 0) + 1);
  const labelIndex = new Map();
  const locations = repositories.map(repository => {
    let label = repository.label;
    const uniqueLabel = labelCounts.get(label) === 1;
    if (!uniqueLabel) {
      const index = (labelIndex.get(label) || 0) + 1;
      labelIndex.set(label, index);
      label += ` (${formatResultNumber(index)})`;
    }
    return {key:scanLocationKey(project.id, repository.key), target:repository.key, label, legacyLabel:uniqueLabel ? repository.label : ''};
  });
  if (project.local_path) locations.push({key:scanLocationKey(project.id, 'local'), target:'local', label:t('scanTarget_local')});
  return locations;
}
function findingMatchesScanLocation(finding, location) {
  if (finding.match !== 'scanner') return false;
  const assetID = finding.asset_id || '';
  if (location.target === 'local') return finding.scan_target === 'local' || assetID.startsWith('code:local:');
  const recordedTarget = assetID.match(/^code:(remote:[0-9a-f]{64}):/)?.[1];
  if (recordedTarget) return recordedTarget === location.target;
  return Boolean(location.legacyLabel && finding.scan_repository === location.legacyLabel);
}
function techStackOptions(projectID) {
  const scope = projectID || filter.project;
  return state.projects.filter(project => !scope || project.id === scope).flatMap(project => {
    const entries = new Map();
    for (const asset of project.assets || []) {
      entries.set(asset.id, {key:stackKey(project.id, asset.id), label:t(asset.kind) + ' · ' + asset.name + ' ' + asset.version});
    }
    for (const finding of project.findings || []) {
      if (finding.match === 'scanner' || entries.has(finding.asset_id)) continue;
      entries.set(finding.asset_id, {
        key:stackKey(project.id, finding.asset_id),
        label:t('previousInventory') + ' · ' + finding.component + ' ' + findingVersionLabel(finding),
      });
    }
    const scanners = scanLocations(project).map(({key, label}) => ({key, label:t('scanner') + ' · ' + label}));
    const prefix = projectID ? '' : project.name + ' · ';
    return [...entries.values(), ...scanners].map(({key, label}) => ({key, label:prefix + label}));
  });
}
function techStackFilterOptions(projectID){
  const options=techStackOptions(projectID);
  if(filter.stack&&!options.some(option=>option.key===filter.stack))filter.stack='';
  return `<option value="">${t('anyTechStack')}</option>`+options.map(option=>`<option value="${esc(option.key)}" ${filter.stack===option.key?'selected':''}>${esc(option.label)}</option>`).join('');
}
function techStackFilterHTML(projectID){return `<select id="tech-stack-filter" aria-label="${t('techStack')}">${techStackFilterOptions(projectID)}</select>`;}
function filtersHTML(showProject,projectID){return `<div class="filters"><div class="search-wrap">${icon('search')}<input id="finding-search" aria-label="${t('search')}" placeholder="${t('search')}" value="${esc(filter.search)}"></div><select id="severity-filter" aria-label="${t('severity')}">${severityOptions(filter.severity)}</select>${showProject?`<select id="project-filter" aria-label="${t('project')}"><option value="">${t('anyProject')}</option>${state.projects.map(p=>`<option value="${p.id}" ${filter.project===p.id?'selected':''}>${esc(p.name)}</option>`).join('')}</select>`:''}${techStackFilterHTML(projectID)}<select id="match-filter" aria-label="${t('match')}"><option value="">${t('anyMatch')}</option>${['review','package','cpe','scanner'].map(m=>`<option value="${m}" ${filter.match===m?'selected':''}>${t(m)}</option>`).join('')}</select></div>`;}
function resultsSummary(matches, total, start, filtered) {
  let text;
  if (matches > findingsPerPage) {
    text = t(filtered ? 'resultsFilteredRange' : 'resultsRange')
      .replace('{start}', formatResultNumber(start + 1))
      .replace('{end}', formatResultNumber(Math.min(start + findingsPerPage, matches)))
      .replace('{matches}', formatResultNumber(matches));
  } else if (filtered) {
    text = t(matches === 1 ? 'resultsFilteredCountOne' : 'resultsFilteredCount')
      .replace('{matches}', formatResultNumber(matches));
  } else {
    text = t(total === 1 ? 'resultsCountOne' : 'resultsCount')
      .replace('{shown}', formatResultNumber(matches));
  }
  return `<div class="results-summary" role="status" aria-live="polite" aria-atomic="true"><span>${t('results')}</span><strong>${esc(text.replace('{total}', formatResultNumber(total)))}</strong></div>`;
}
function formatResultNumber(value) {
  return value.toLocaleString(formatLocale());
}
function findingPagination(pages) {
  if (pages <= 1) return '';
  const pageLabel = t('findingPage').replace('{page}', formatResultNumber(findingsPage)).replace('{pages}', formatResultNumber(pages));
  return `<nav class="findings-pagination" aria-label="${t('findingPages')}"><button type="button" class="button secondary small" data-finding-page="previous" ${findingsPage === 1 ? 'disabled' : ''}>${t('previousPage')}</button><span>${esc(pageLabel)}</span><button type="button" class="button secondary small" data-finding-page="next" ${findingsPage === pages ? 'disabled' : ''}>${t('nextPage')}</button></nav>`;
}
function findingsTable(projectID) {
  const search = filter.search.toLowerCase();
  const [stackProject, stackAsset, scanTarget] = filter.stack ? JSON.parse(filter.stack) : [];
  const items = [];
  let total = 0;
  let scanSeverityCounts;
  for (const project of state.projects) {
    if (projectID && projectID !== project.id) continue;
    const findings = project.findings || [];
    total += findings.length;
    if (!projectID && filter.project && filter.project !== project.id) continue;
    if (stackProject && stackProject !== project.id) continue;
    const location = scanTarget && scanLocations(project).find(candidate => candidate.target === scanTarget);
    if (scanTarget && !location) continue;
    if (location) scanSeverityCounts = {};
    for (const finding of findings) {
      if (location ? !findingMatchesScanLocation(finding, location) :
          stackProject && (finding.match === 'scanner' || finding.asset_id !== stackAsset)) continue;
      if ((filter.match && filter.match !== finding.match) ||
          (search && ![finding.id, finding.title, finding.component].join(' ').toLowerCase().includes(search))) continue;
      let severity = finding.severity;
      if (location) {
        if (!findingSeverities.includes(severity)) severity = 'UNKNOWN';
        scanSeverityCounts[severity] = (scanSeverityCounts[severity] || 0) + 1;
      }
      if (filter.severity && filter.severity !== severity) continue;
      items.push({finding, project});
    }
  }
  items.sort((a, b) => findingSeverities.indexOf(a.finding.severity) - findingSeverities.indexOf(b.finding.severity));
  const pages = Math.max(1, Math.ceil(items.length / findingsPerPage));
  findingsPage = Math.max(1, Math.min(findingsPage, pages));
  const start = (findingsPage - 1) * findingsPerPage;
  const filtered = filter.search || filter.severity || filter.stack || filter.match || (!projectID && filter.project);
  const severitySummary = scanSeverityCounts
    ? `<div class="scan-location-severity"><span>${t('severityBreakdown')}</span>${severityCountList(scanSeverityCounts)}</div>` : '';
  const toolbar = `<div class="findings-toolbar">${resultsSummary(items.length, total, start, filtered)}${findingPagination(pages)}</div>` + severitySummary;
  if (!items.length) {
    return toolbar + (filtered ? empty('noMatchingFindings','noMatchingFindingsSub','vulnerabilities') : empty('noFindings','noFindingsSub','vulnerabilities'));
  }

  const rows = items.slice(start, start + findingsPerPage).map(({finding:f, project}) => `<tr data-finding="${esc(f.id)}" data-asset="${esc(f.asset_id)}" data-project="${esc(project.id)}" tabindex="0" role="button" aria-label="${esc(f.id+' '+f.title)}"><td><span class="finding-title">${esc(f.title||f.id)}</span><span class="finding-id">${esc(f.id)} · ${esc(f.sources.join(' + '))}</span></td><td>${esc(f.component)}<span class="component-version">${esc(findingVersionLabel(f))}</span></td><td>${pill(t(severityKey(f.severity)),severityKey(f.severity))}</td><td>${pill(t(f.match),f.match==='review'?'review':'')}</td>${!projectID?`<td>${esc(project.name)}</td>`:''}</tr>`).join('');
  return toolbar + `<div class="table-wrap"><table class="table"><thead><tr><th>${t('advisory')}</th><th>${t('component')}</th><th>${t('severity')}</th><th>${t('match')}</th>${!projectID?`<th>${t('project')}</th>`:''}</tr></thead><tbody>${rows}</tbody></table></div>`;
}
function bindFilters(projectID) {
  const updateResults = () => {
    findingsPage = 1;
    $('#finding-results').innerHTML = findingsTable(projectID);
  };
  $('#finding-search')?.addEventListener('input', e => {
    filter.search = e.target.value;
    updateResults();
  });
  for (const [id,key] of [['severity-filter','severity'],['project-filter','project'],['tech-stack-filter','stack'],['match-filter','match']]) {
    $('#'+id)?.addEventListener('change', e => {
      filter[key] = e.target.value;
      if (key === 'project') $('#tech-stack-filter').innerHTML = techStackFilterOptions(projectID);
      updateResults();
    });
  }
}
function turnFindingPage(direction) {
  const [page, projectID] = route();
  const results = $('#finding-results');
  findingsPage += direction === 'next' ? 1 : -1;
  results.innerHTML = findingsTable(page === 'project' ? projectID : undefined);
  const button = results.querySelector(`[data-finding-page="${direction}"]:not(:disabled)`) ||
    results.querySelector('[data-finding-page]:not(:disabled)');
  button?.focus({preventScroll:true});
}
function componentSyncControls(project,asset){const selected=componentSyncSeveritySelection.get(stackKey(project.id,asset.id))||'';return `<div class="stack-sync-controls"><label class="sync-scope stack-sync-severity"><span>${t('syncSeverity')}</span><select data-sync-component-severity data-project-id="${esc(project.id)}" data-asset-id="${esc(asset.id)}" title="${t('severitySyncHint')}" ${project.syncing?'disabled':''}>${severityOptions(selected)}</select></label><button class="button secondary small stack-sync" data-action="sync-asset" data-id="${esc(project.id)}" data-asset="${esc(asset.id)}" ${project.syncing?'disabled':''}>${icon('refresh')}${t('sync')}</button></div>`;}
function componentCriticalCount(project,asset){const count=(project.findings||[]).filter(f=>f.asset_id===asset.id&&f.severity==='CRITICAL').length;return `<div class="stack-critical-count"><span>${t('critical')}</span>${pill(count.toLocaleString(formatLocale()),count?'critical':'')}</div>`;}
function renderProject(id){const p=state.projects.find(p=>p.id===id);if(!p){location.hash='projects';return;}
  const latestRun = p.runs?.[0];
  const fullRun = latestFullRun(p);
  const workflow = workflowRun(p, latestRun, true);
  let statusBadge = workflow && latestRun?.status === 'paused' ? '' : projectStatus(p);
  if (!p.syncing && fullRun?.status === 'interrupted') {
    statusBadge = pill(interruptionMessage(fullRun, true), 'interrupted full-sync-interruption');
  }
  $('#main').innerHTML=heading(p.name,p.description||t('projectPanelSub'),`<button class="button secondary" data-action="edit-project" data-id="${p.id}" ${p.syncing?'disabled':''}>${icon('edit')}${t('editProject')}</button><button type="button" class="button secondary" data-action="scan-code" data-id="${esc(p.id)}" ${p.syncing?'disabled':''}>${icon('scanCode')}${t('runCodeScan')}</button>${syncControls(p)}`)+`<div class="project-meta">${statusBadge}${pill(t(p.schedule))}${validDate(p.last_sync)?pill(t('lastSync')+' · '+fmtDate(p.last_sync)):''}${validDate(p.data_checked_at)?pill(t('sourceDataChecked')+' · '+fmtDate(p.data_checked_at)):''}${validDate(p.next_run)?pill(t('nextRun')+' · '+fmtDate(p.next_run)):''}${projectRepositoryLinks(p)}</div>${workflow}<div class="tabs">${['vulnerabilities','techStack','activity'].map(tab=>`<button class="tab ${projectTab===tab?'active':''}" data-tab="${tab}">${t(tab)}${tab==='vulnerabilities'?' ('+(p.findings?.length||0)+')':''}</button>`).join('')}</div>${fullRun&&['partial','failed','interrupted','stopped'].includes(fullRun.status)?`<div class="notice">${t('incomplete')}</div>`:''}${(latestRun?.asset_id||latestRun?.severity||latestRun?.mode==='code')&&['partial','failed','interrupted','stopped'].includes(latestRun.status)?`<div class="notice">${t(latestRun.mode==='code'?'codeScanIncomplete':'scopedSyncIncomplete')}</div>`:''}${p.assessed_revision!==p.revision&&p.assessed_revision?`<div class="notice info">${t('inventoryChanged')}</div>`:''}<div id="project-tab-content"></div>`;const content=$('#project-tab-content');if(projectTab==='vulnerabilities'){content.innerHTML=filtersHTML(false,id)+`<div class="panel" id="finding-results">${findingsTable(id)}</div>`;bindFilters(id);}else if(projectTab==='techStack'){content.innerHTML=`<div class="stack-toolbar"><button type="button" class="button primary" data-action="add-component" data-id="${esc(p.id)}" ${p.syncing?'disabled':''}>${t('addComponent')}</button></div>`+(p.assets.length?`<div class="stack-grid">${p.assets.map(a=>`<div class="stack-card"><div class="eyebrow">${t(a.kind)}</div><strong>${esc(a.name)}</strong><p>${esc(a.version)}${a.ecosystem?' · '+esc(a.ecosystem):''}</p>${a.cpe?`<code>${esc(a.cpe)}</code>`:''}${componentCriticalCount(p,a)}${componentSyncControls(p,a)}</div>`).join('')}</div>`:empty('noStack','noStackSub','stack'));}else content.innerHTML=`<div class="panel">${activityList(allRuns().filter(r=>r.project_id===id))}</div>`;}
function field(name,label,value='',type='text',extra=''){return `<label><span>${t(label)}</span><input type="${type}" name="${name}" value="${esc(value)}" ${extra}></label>`;}
function providerOptions(selected){return ['public','openai','claude'].map(v=>`<option value="${v}" ${selected===v?'selected':''}>${t(v)}</option>`).join('');}
function cacheNumber(n){return Number(n||0).toLocaleString(formatLocale());}
function cacheUsageHTML(stats={}){return `<span>${t('cacheEntries')}: <strong>${cacheNumber(stats.entries)}</strong></span><span>${t('cacheSize')}: <strong>${((stats.bytes||0)/1048576).toFixed(2)} MiB</strong></span>`;}
function cacheMetricsHTML(stats={}){const hits=stats.hits||0,misses=stats.misses||0,rate=hits+misses?((hits/(hits+misses))*100).toFixed(1)+'%':'—';return `<div><span>${t('cacheHits')}</span><strong>${cacheNumber(hits)}</strong></div><div><span>${t('cacheMisses')}</span><strong>${cacheNumber(misses)}</strong></div><div><span>${t('cacheHitRate')}</span><strong>${rate}</strong></div><div><span>${t('cacheEvictions')}</span><strong>${cacheNumber(stats.evictions)}</strong></div>`;}
function updateCacheMetrics(stats){const usage=$('#cache-usage'),metrics=$('#cache-metrics');if(usage)usage.innerHTML=cacheUsageHTML(stats);if(metrics)metrics.innerHTML=cacheMetricsHTML(stats);}
function cacheSettingsHTML(){
  const stats=state.cache_stats||{},settings=state.settings,locale=formatLocale(),number=n=>Number(n||0).toLocaleString(locale);
  const entries=settings.cache_max_entries||10000,mib=settings.cache_max_mib||512;
  const capacity=t('cacheCapacity').replace('{entries}',number(entries)).replace('{mib}',number(mib));
  return `<section class="settings-section"><h3>${t('cacheSettings')}</h3><p>${t('cacheHint')}</p><div class="form-grid"><label><span>${t('cacheHours')}</span><input name="cache_hours" type="number" min="1" max="168" step="1" required value="${esc(settings.cache_hours||6)}"></label><label><span>${t('cacheMaxEntries')}</span><input name="cache_max_entries" type="number" min="100" max="1000000" step="1" required value="${esc(entries)}"></label><label><span>${t('cacheMaxMiB')}</span><input name="cache_max_mib" type="number" min="16" max="4096" step="1" required value="${esc(mib)}"></label><div class="cache-stats" id="cache-usage">${cacheUsageHTML(stats)}</div></div><div class="cache-metrics" id="cache-metrics">${cacheMetricsHTML(stats)}</div><p class="form-note">${t('cacheStatsHint')}</p><p class="form-note">${esc(capacity)}</p><p class="form-note">${t('cacheLimitsHint')}</p></section>`;
}
function storagePathsHTML(){const paths=state.storage_paths||{};return `<dl class="storage-paths"><div><dt>${t('databaseFile')}</dt><dd><code>${esc(paths.database||'—')}</code></dd></div><div><dt>${t('keyFile')}</dt><dd><code>${esc(paths.key||'—')}</code></dd></div></dl>`;}
async function browseFolder(input, title, directory = input.value) {
  const chosen = await invoke('ChooseFolder', t(title), directory);
  if (chosen && input.isConnected) input.value = chosen;
}
function storageDirectoryHTML() {
  const warning = state.storage_warning;
  return `<div class="storage-directory">
    <label for="data-directory"><span>${t('dataDirectory')}</span></label>
    <div class="folder-picker storage-directory-controls">
      <input id="data-directory" value="${esc(state.data_directory||'')}" aria-describedby="data-directory-hint">
      <button type="button" class="button secondary" data-action="browse-data-directory">${t('browseFolder')}</button>
      <button type="button" class="button secondary" data-action="use-data-directory">${t('useDataDirectory')}</button>
      ${state.data_directory !== state.default_data_directory ? `<button type="button" class="button secondary" data-action="reset-data-directory">${t('resetDataDirectory')}</button>` : ''}
    </div>
    <p class="form-note" id="data-directory-hint">${t('dataDirectoryHint')}</p>
    <p class="notice" id="data-directory-status" role="status" ${warning?'':'hidden'}>${warning?esc(t(warning)):''}</p>
  </div>`;
}
async function changeDataDirectory(directory) {
  if (changingDataDirectory) return;
  const form = $('#settings-form');
  if ($('button[type="submit"]', form)?.disabled) return;
  const previousDirectory = state.data_directory;
  changingDataDirectory = true;
  const buttons = $$('button:not(:disabled)', form);
  for (const button of buttons) button.disabled = true;
  const status = $('#data-directory-status');
  status.textContent = t('changingDataDirectory');
  status.hidden = false;
  try {
    await invoke('ChangeDataDirectory', directory);
    await refresh(false);
    if (state.data_directory !== previousDirectory) {
      projectTokenSetup = null;
      projectDeleteDraft = null;
    }
    const storage = $('.storage-directory');
    if (storage && state.data_directory === previousDirectory) storage.outerHTML = storageDirectoryHTML();
    else render();
    toast(t(state.storage_warning || 'dataDirectoryChanged'), Boolean(state.storage_warning));
  } catch (err) {
    status.textContent = err.message;
  } finally {
    changingDataDirectory = false;
    for (const button of buttons) button.disabled = false;
  }
}
const scannerLabels = {govulncheck:'govulncheck', npm:'npm audit', composer:'composer audit', 'pip-audit':'pip-audit', trivy:'Trivy', snyk:'Snyk'};
const trivyInstall = 'https://trivy.dev/docs/latest/getting-started/installation/';
const nodeInstall = 'https://nodejs.org/en/download';
const composerInstall = 'https://getcomposer.org/doc/00-intro.md';
const snykInstall = 'https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli';
const snykAuth = 'https://docs.snyk.io/developer-tools/snyk-cli/authenticate-to-use-the-cli';
const scannerInstallations = {
  govulncheck: {
    darwin:['scannerGoInstallMac', 'go install golang.org/x/vuln/cmd/govulncheck@latest', 'https://go.dev/doc/tutorial/govulncheck#install-and-run-govulncheck'],
    common:['scannerGoInstall', 'go install golang.org/x/vuln/cmd/govulncheck@latest', 'https://go.dev/doc/tutorial/govulncheck#install-and-run-govulncheck'],
  },
  npm: {
    darwin:['scannerInstallCommand', 'brew install node', 'https://formulae.brew.sh/formula/node'],
    windows:['scannerNodeWindows', '', nodeInstall],
    debian:['scannerInstallCommand', 'sudo apt install nodejs npm', nodeInstall],
    fedora:['scannerInstallCommand', 'sudo dnf install nodejs npm', nodeInstall],
    arch:['scannerInstallCommand', 'sudo pacman -S nodejs npm', nodeInstall],
    alpine:['scannerInstallCommand', 'apk add nodejs npm', nodeInstall],
    common:['scannerInstallGeneric', '', nodeInstall],
  },
  composer: {
    darwin:['scannerInstallCommand', 'brew install composer', 'https://formulae.brew.sh/formula/composer'],
    windows:['scannerComposerWindows', '', composerInstall+'#installation-windows'],
    debian:['scannerInstallCommand', 'sudo apt install composer', composerInstall+'#globally'],
    arch:['scannerInstallCommand', 'sudo pacman -S composer', composerInstall+'#globally'],
    common:['scannerInstallGeneric', '', composerInstall+'#globally'],
  },
  'pip-audit': {
    darwin:['scannerInstallCommand', 'brew install pip-audit', 'https://formulae.brew.sh/formula/pip-audit'],
    common:['scannerPipAuditInstall', 'pipx install pip-audit', 'https://github.com/pypa/pip-audit#installation'],
  },
  trivy: {
    darwin:['scannerInstallCommand', 'brew install trivy', trivyInstall+'#homebrew-official'],
    windows:['scannerTrivyWindows', '', trivyInstall+'#windows-official'],
    debian:['scannerTrivyRepository', 'sudo apt-get install trivy', trivyInstall+'#debianubuntu-official'],
    fedora:['scannerTrivyRepository', 'sudo dnf install trivy', trivyInstall+'#rhelcentos-official'],
    arch:['scannerInstallCommand', 'sudo pacman -S trivy', trivyInstall+'#arch-linux-community'],
    common:['scannerInstallGeneric', '', trivyInstall+'#github-release-official'],
  },
  snyk: {
    darwin:['scannerInstallCommand', 'brew install snyk/tap/snyk', snykInstall+'#package-managers'],
    windows:['scannerSnykWindows', '', snykInstall+'#direct-binary-download'],
    common:['scannerSnykLinux', '', snykInstall+'#direct-binary-download'],
  },
};
const scannerStatusKeys = {ready:'scannerReady',missing:'scannerMissing',permission:'scannerPermission',path:'scannerPath',failed:'scannerFailed',timeout:'scannerTimeout'};

function snykSetupHTML() {
  return `<div class="scanner-check snyk-setup">
    <p>${t('scannerSnykInstall')} <a href="${snykInstall}" target="_blank" rel="noreferrer">${t('scannerInstallGuide')} ↗</a></p>
    <p>${t('scannerSnykSetup')} <a href="${snykAuth}" target="_blank" rel="noreferrer">${t('scannerSnykTokenGuide')} ↗</a></p>
    <p>${t('scannerSnykProject')}</p>
    <button type="button" class="button secondary small" data-action="focus-snyk-token">${t('scannerSnykGoToToken')}</button>
  </div>`;
}

function scannerSettingsHTML(names) {
  return Object.entries(scannerLabels).map(([name,label]) => {
    const checkable = Object.hasOwn(scannerInstallations, name);
    const id = 'scanner-status-' + name;
    const row = `<label class="check-row"><input type="checkbox" name="scanner_${name}" ${names[name]?'checked':''} ${checkable?`data-scanner-check="${name}" aria-describedby="${id}"`:''}><span><strong>${label}</strong></span></label>`;
    return checkable ? `<div class="scanner-option">${row}${name === 'snyk' ? snykSetupHTML() : ''}<div class="scanner-check" id="${id}" aria-live="polite" hidden></div></div>` : row;
  }).join('');
}
function scannerResultHTML(name, result) {
  const {platform,status} = result;
  let guidance = '';
  if (status === 'permission') {
    guidance = `<p>${t(platform === 'windows' ? 'scannerPermissionsWindows' : 'scannerPermissionsUnix')}</p>`;
    if (platform === 'darwin') guidance += `<p>${t('scannerPermissionsDarwin')}</p><a href="https://support.apple.com/en-us/102445" target="_blank" rel="noreferrer">${t('scannerPermissionGuide')} ↗</a>`;
    if (platform === 'windows') guidance += `<a href="https://learn.microsoft.com/windows/security/identity-protection/access-control/access-control" target="_blank" rel="noreferrer">${t('scannerPermissionGuide')} ↗</a>`;
  } else if (platform && status !== 'ready') {
    const installs = scannerInstallations[name];
    const [hint,command,url] = installs[platform] || installs.common;
    const pathHint = {darwin:'scannerPathDarwin',windows:'scannerPathWindows'}[platform] || 'scannerPathLinux';
    guidance = `<p>${t(hint)}</p>${command?`<code class="scanner-command">${esc(command)}</code>`:''}<p>${t(pathHint)}</p><a href="${url}" target="_blank" rel="noreferrer">${t('scannerInstallGuide')} ↗</a>`;
  }
  const statusKey = name === 'snyk' && status === 'ready' ? 'scannerSnykReady' : scannerStatusKeys[status] || 'scannerFailed';
  return `<p class="scanner-status ${status === 'ready' ? 'ready' : 'warning'}">${t(statusKey)}</p>${result.path?`<code class="scanner-path">${esc(result.path)}</code>`:''}${result.detail?`<p>${esc(result.detail)}</p>`:''}${guidance}<button type="button" class="button secondary small scanner-recheck" data-action="check-scanner" data-scanner="${name}">${t('scannerCheckAgain')}</button>`;
}
async function checkScanner(input) {
  const name = input.dataset.scannerCheck;
  const panel = $('#scanner-status-' + name);
  if (!panel) return;
  const request = String(Number(panel.dataset.request || 0) + 1);
  panel.dataset.request = request;
  panel.hidden = !input.checked;
  if (!input.checked) {
    panel.textContent = '';
    return;
  }
  panel.textContent = t('scannerChecking');
  let result;
  try {
    result = await invoke('CheckScanner', name);
  } catch {
    result = {status:'failed'};
  }
  if (panel.isConnected && panel.dataset.request === request) panel.innerHTML = scannerResultHTML(name,result);
}
const credentialLabels = {nvd:'NVD API key', openai:'OpenAI API key', claude:'Claude API key', snyk:'snykTokenLabel', github:'githubTokenLabel'};
const credentialDots = '••••••';
const credentialPreviewRequests = new WeakMap();

function credentialToggleLabel(name, visible) {
  return t(visible ? 'hideCredential' : 'showCredential') + ' · ' + t(credentialLabels[name]);
}

function setCredentialVisibility(field, visible) {
  field.classList.remove('credential-preview-selected');
  const button = $('[data-credential-toggle]', field);
  const label = credentialToggleLabel(button.dataset.credentialToggle, visible);
  button.setAttribute('aria-label', label);
  button.setAttribute('aria-pressed', String(visible));
  button.title = label;
  button.innerHTML = icon(visible ? 'eyeOff' : 'eye');
  if (!visible) {
    credentialPreviewRequests.delete(button);
    $('[data-credential-input]', field).type = 'password';
    const preview = $('.credential-preview', field);
    preview.classList.remove('credential-preview-inline');
    preview.textContent = '';
  }
}

async function toggleCredential(button) {
  const form = button.closest('form');
  if ($('button[type="submit"]', form).disabled) return;
  const field = button.closest('.credential-field');
  const input = $('[data-credential-input]', field);
  const name = button.dataset.credentialToggle;
  const visible = button.getAttribute('aria-pressed') !== 'true';
  const hasSavedKey = input.dataset.credentialSaved === 'true' && !clearing.has(name);
  input.placeholder = !visible && hasSavedKey ? credentialDots : '';
  setCredentialVisibility(field, visible);
  if (!visible) return;

  if (input.value) {
    input.type = 'text';
    return;
  }
  if (clearing.has(name)) {
    $('.credential-preview', field).textContent = t('noSavedCredential');
    return;
  }

  const request = invoke('SavedCredentialPreview', name);
  credentialPreviewRequests.set(button, request);
  const isCurrent = () => button.isConnected && credentialPreviewRequests.get(button) === request && !input.value;
  try {
    const masked = await request;
    if (isCurrent()) {
      input.dataset.credentialSaved = String(Boolean(masked));
      const preview = $('.credential-preview', field);
      preview.classList.toggle('credential-preview-inline', Boolean(masked));
      preview.textContent = masked || t('noSavedCredential');
    }
  } catch {
    if (isCurrent()) {
      setCredentialVisibility(field, false);
      input.placeholder = hasSavedKey ? credentialDots : '';
      toast(t('credentialPreviewError'), true);
    }
  } finally {
    if (credentialPreviewRequests.get(button) === request) credentialPreviewRequests.delete(button);
  }
}

function clearCredential(button) {
  const field = button.closest('.credential-field');
  clearing.add(button.dataset.clearToken);
  const input = $('[data-credential-input]', field);
  input.value = '';
  input.placeholder = '';
  setCredentialVisibility(field, false);
  button.textContent = t('removeKey');
}

function handleCredentialKeydown(event) {
  const control = event.target.closest('[data-credential-input], [data-credential-toggle]');
  if (!control || event.isComposing || changingDataDirectory) return false;
  const field = control.closest('.credential-field');
  const input = $('[data-credential-input]', field);
  if (input.value || $('button[type="submit"]', input.form).disabled) return false;

  const selectAll = (event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === 'a';
  if (selectAll && (input.placeholder || $('.credential-preview-inline', field))) {
    event.preventDefault();
    input.focus();
    field.classList.add('credential-preview-selected');
    return true;
  }
  if (!field.classList.contains('credential-preview-selected') || ['Alt', 'Control', 'Meta', 'Shift'].includes(event.key)) return false;

  field.classList.remove('credential-preview-selected');
  if (event.key !== 'Backspace' && event.key !== 'Delete') return false;
  event.preventDefault();
  clearCredential($('[data-clear-token]', field));
  return true;
}

function credentialSettingsHTML() {
  const back = projectTokenSetup && location.hash === githubTokenSettingsHash
    ? `<button type="button" class="button secondary small github-token-return" data-action="return-to-project-form">${t('returnToProjectForm')}</button>`
    : '';
  const fields = Object.entries(credentialLabels).map(([name, label]) => {
    const id = 'credential-' + name;
    const toggleLabel = esc(credentialToggleLabel(name, false));
    const saved = Boolean(state.saved_token_status?.[name]);
    const hint = name === 'snyk' ? `<p class="credential-hint" id="${id}-hint">${t('snykTokenHint')}</p>` : '';
    return `<div class="credential-field">
      <label for="${id}" class="token-label">${t(label)}<span class="token-configured">${t(state.token_status[name]?'configured':'notConfigured')}</span></label>
      <div class="credential-input">
        <input type="password" name="token_${name}" id="${id}" data-credential-input data-credential-saved="${saved}" placeholder="${saved ? credentialDots : ''}" autocomplete="new-password" spellcheck="false" autocapitalize="off"${hint ? ` aria-describedby="${id}-hint"` : ''}>
        <output class="credential-preview" id="${id}-preview"></output>
        <button type="button" class="icon-button credential-eye" data-action="toggle-credential" data-credential-toggle="${name}" aria-label="${toggleLabel}" title="${toggleLabel}" aria-controls="${id} ${id}-preview" aria-pressed="false">${icon('eye')}</button>
      </div>
      <button class="clear-token" type="button" data-clear-token="${name}">${t('clear')}</button>
      ${hint}
    </div>`;
  }).join('');
  return `<section class="settings-section"><h3>${t('tokens')}</h3><p>${t('tokensHint')}</p><div class="form-grid">${fields}</div>${back}</section>`;
}

function renderSettings(){const s=state.settings;clearing=new Set();$('#main').innerHTML=heading(t('settings'),t('settingsSub'))+`<form id="settings-form" class="settings-layout panel"><section class="settings-section"><h3>${t('general')}</h3><div class="form-grid"><label><span>${t('uiLanguage')}</span><select name="language">${languageOptions()}</select></label></div></section><section class="settings-section"><h3>${t('sourceSettings')}</h3><p>${t('sourceSettingsHint')}</p>${['nvd','cve','osv'].map(n=>`<label class="check-row"><input type="checkbox" name="source_${n}" ${s.sources[n]?'checked':''}><span><strong>${{nvd:'NIST NVD',cve:'CVE Program',osv:'OSV.dev'}[n]}</strong><small>${t({nvd:'discovery',cve:'enrichment',osv:'packageMatching'}[n])}</small></span></label>`).join('')}<div class="form-grid">${field('nvd_url','nvdEndpoint',s.nvd_url,'url','required')}${field('cve_url','cveEndpoint',s.cve_url,'url','required')}${field('osv_url','osvEndpoint',s.osv_url,'url','required')}</div></section>${cacheSettingsHTML()}${credentialSettingsHTML()}<section class="settings-section"><h3>${t('aiSettings')}</h3><p>${t('aiSettingsHint')}</p><div class="form-grid"><label><span>${t('defaultProvider')}</span><select name="ai_provider">${providerOptions(s.ai_provider)}</select></label><div></div>${field('openai_model','openaiModel',s.openai_model,'text','placeholder="e.g. a model ID enabled for your API account"')}${field('claude_model','claudeModel',s.claude_model,'text','placeholder="e.g. a model ID enabled for your API account"')}</div></section><section class="settings-section"><h3>${t('scannerSettings')}</h3><p>${t('scannerSettingsHint')}</p><div class="form-grid">${scannerSettingsHTML(s.scanners)}</div></section><section class="settings-section"><p class="storage-note">${t('storageNote')}</p>${storageDirectoryHTML()}${storagePathsHTML()}</section><div class="settings-actions"><button class="button primary" type="submit">${t('saveSettings')}</button><span class="form-error" id="settings-error"></span></div></form>`;$('#settings-form').addEventListener('submit',saveSettings);$$('[data-scanner-check]:checked').forEach(checkScanner);}
function render(){if(pendingPageRender)return;renderNav();const [page,id,view]=route();if(location.hash===newProjectHash)renderProjectEditor();else if(page==='projects')$('#main').innerHTML=heading(t('projects'),t('projectsSub'),button('addProject','new-project',true,'plus'))+`<div class="panel"><div class="panel-head"><h2>${t('yourProjects')} <span class="muted">(${state.projects.length})</span></h2></div>${projectList(state.projects, true)}</div>`;else if(page==='vulnerabilities'){$('#main').innerHTML=heading(t('vulnerabilities'),t('vulnsSub'),state.projects.length?syncAllControls(true):'')+filtersHTML(true)+`<div class="panel" id="finding-results">${findingsTable()}</div>`;bindFilters();}else if(page==='activity')$('#main').innerHTML=heading(t('activity'),t('activitySub'))+`<div class="panel">${activityList()}</div>`;else if(page==='settings')renderSettings();else if(page==='project'){if(view==='edit')renderProjectEditor(id);else if(view==='delete')renderProjectDeletion(id);else renderProject(id);}else renderOverview();mountActiveSyncs();}
function componentFields(a={},removable=true){const el=document.createElement('div');el.className='asset-field';el.dataset.id=a.id||'';el.innerHTML=`<div class="asset-top"><label><span>${t('category')}</span><select data-field="kind">${['language','database','container','docker','webserver','ai','library','other'].map(k=>`<option value="${k}" ${(a.kind||'library')===k?'selected':''}>${t(k)}</option>`).join('')}</select></label><label><span>${t('name')}</span><input data-field="name" value="${esc(a.name)}" required placeholder="org.apache.logging.log4j:log4j-core" maxlength="300"></label><label><span>${t('version')}</span><input data-field="version" value="${esc(a.version)}" required placeholder="2.14.1" maxlength="100"></label>${removable?`<button type="button" class="icon-button asset-remove" aria-label="${t('removeComponent')}">×</button>`:''}</div><div class="asset-bottom"><label><span>${t('ecosystem')}</span><select data-field="ecosystem"><option value="">—</option>${['Go','npm','PyPI','Maven','Packagist','crates.io','RubyGems','NuGet','Hex','Pub','Debian','Alpine','GIT'].map(e=>`<option ${a.ecosystem===e?'selected':''}>${e}</option>`).join('')}</select></label><label><span>${t('cpeLabel')}</span><input data-field="cpe" value="${esc(a.cpe)}" placeholder="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"></label></div>`;return el;}
function openComponent(id){const p=state.projects.find(p=>p.id===id);if(!p||p.syncing)return false;componentDraft={...p,assets:p.assets.map(a=>({...a}))};$('#component-form').reset();$('#component-error').textContent='';$('#component-project').textContent=t('componentProject').replace('{project}',p.name);const fields=$('#component-fields');fields.innerHTML='';const el=componentFields({},false);fields.append(el);localize($('#component-dialog'));$('#component-dialog').showModal();el.querySelector('[data-field="name"]').focus();return true;}
async function saveComponent(e){e.preventDefault();if(!componentDraft)return;const submit=$('#save-component');submit.disabled=true;const p=componentDraft,asset={};$$('[data-field]',$('#component-fields')).forEach(input=>asset[input.dataset.field]=input.value.trim());const body={};for(const key of ['name','description','repository','repository_urls','local_path','schedule','scan_code','revision'])body[key]=p[key];body.assets=[...p.assets,asset];try{await invoke('UpdateProject',p.id,body);$('#component-dialog').close();componentDraft=null;await refresh(false);projectTab='techStack';render();toast(t('saved'));}catch(err){$('#component-error').textContent=err.message;}finally{submit.disabled=false;}}
const projectTextFields = ['name', 'description', 'local_path', 'schedule'];

function repositoryField(url = '') {
  const row = document.createElement('div');
  row.className = 'project-repository';
  row.innerHTML = `<input type="url" data-repository-url value="${esc(url)}" aria-label="${esc(t('repository'))}" placeholder="https://github.com/your-org/project"><button type="button" class="icon-button" data-action="remove-repository" aria-label="${esc(t('removeRepositoryURL'))}">×</button>`;
  return row;
}

function projectFormValues(form, trim = false) {
  const value = input => trim ? input.value.trim() : input.value;
  const body = {scan_code: form.elements.scan_code.checked};
  for (const key of projectTextFields) body[key] = value(form.elements[key]);
  const repositories = $$('[data-repository-url]', form).map(value);
  body.repository_urls = trim ? repositories.filter(Boolean) : repositories;
  body.assets = $$('.asset-field', form).map(row => {
    const asset = {id: row.dataset.id};
    for (const field of $$('[data-field]', row)) asset[field.dataset.field] = value(field);
    return asset;
  });
  return body;
}

function mountProjectForm(container, project) {
  const form = $('#project-form-template').content.firstElementChild.cloneNode(true);
  form.dataset.language = lang;
  if (project?.id) {
    form.dataset.projectId = project.id;
    form.dataset.revision = project.revision;
    for (const warning of $$('[data-project-removal-warning]', form)) warning.hidden = false;
  }
  form.elements.schedule.innerHTML = ['off', 'hourly', 'daily', 'weekly'].map(key => `<option value="${key}">${t(key)}</option>`).join('');
  for (const key of projectTextFields) form.elements[key].value = project?.[key] ?? (key === 'schedule' ? 'off' : '');
  form.elements.scan_code.checked = !!project?.scan_code;
  const repositories = projectRepositories(project);
  const list = $('[data-project-repositories]', form);
  for (const url of repositories.length ? repositories : ['']) list.append(repositoryField(url));
  const assets = $('[data-project-assets]', form);
  for (const asset of project?.assets ?? [{}]) assets.append(componentFields(asset));
  form.addEventListener('submit', saveProject);
  container.replaceChildren(form);
  localize(form);
}

function openNewProject() {
  newProjectReturnHash = location.hash || '#overview';
  location.hash = newProjectHash;
}

function renderProjectEditor(id) {
  const project = id ? state.projects.find(project => project.id === id) : undefined;
  if (id && !project) {
    location.hash = 'projects';
    return;
  }
  const previous = $('#project-editor form');
  const sameForm = previous?.dataset && previous.dataset.projectId === id;
  if (sameForm && (previous.dataset.language === lang || $('button[type="submit"]', previous).disabled)) return;

  const returningDraft = projectDeleteDraft && projectDeleteDraft.id === id ? projectDeleteDraft :
    projectTokenSetup?.returnHash === location.hash ? projectTokenSetup.draft : null;
  const draft = sameForm
    ? {...project, ...projectFormValues(previous), revision: previous.dataset.revision}
    : returningDraft ?? project;
  const remove = project
    ? `<button type="button" class="button danger delete-project-button" data-action="delete-project" data-id="${esc(id)}">${t('deleteProject')}</button>`
    : '';
  $('#main').innerHTML = heading(t(project ? 'editProject' : 'newProject'), '', remove) + '<div id="project-editor" class="panel project-editor"></div>';
  mountProjectForm($('#project-editor'), draft);
  projectDeleteDraft = null;
}

function openProjectDeletion(id) {
  if (!state.projects.some(project => project.id === id)) return;
  const editor = $('#project-editor form');
  if (editor?.dataset?.projectId === id) {
    if ($('button[type="submit"]', editor).disabled) return;
    projectDeleteDraft = {...projectFormValues(editor), id, revision:editor.dataset.revision};
  }
  location.hash = 'project/' + id + '/delete';
}

function updateProjectDeletionForm(form, project) {
  $('[data-delete-project-busy]', form).hidden = !project.syncing;
  $('[data-delete-project-submit]', form).disabled = project.syncing || form.dataset.pending === 'true' ||
    !form.elements.confirmation.value || form.elements.confirmation.value !== project.name;
}

function renderProjectDeletion(id) {
  const project = state.projects.find(project => project.id === id);
  if (!project) {
    location.hash = 'projects';
    return;
  }
  const previous = $('#delete-project-form');
  if (previous?.dataset?.projectId === id && previous.dataset.projectName === project.name &&
      previous.dataset.language === lang) {
    updateProjectDeletionForm(previous, project);
    return;
  }

  $('#main').innerHTML = heading(t('deleteProject')) + `<form id="delete-project-form" class="panel project-delete-form" data-project-id="${esc(id)}" data-project-name="${esc(project.name)}" data-language="${esc(lang)}">
    <p class="notice project-delete-notice">${t('deleteProjectNotice')}</p>
    <p id="delete-project-name" class="project-delete-name"><strong>${esc(project.name)}</strong></p>
    <label for="delete-project-confirmation"><span>${t('deleteProjectTypeName')}</span></label>
    <input id="delete-project-confirmation" name="confirmation" required aria-describedby="delete-project-name" autocomplete="off" autocapitalize="off" spellcheck="false">
    <p class="form-error" role="status" data-delete-project-busy hidden>${t('deleteProjectBusy')}</p>
    <p class="form-error" role="alert" data-delete-project-error></p>
    <div class="project-form-actions">
      <button type="button" class="button secondary" data-action="cancel-project-deletion">${t('cancel')}</button>
      <button type="submit" class="button danger delete-project-button" data-delete-project-submit disabled>${t('deleteProject')}</button>
    </div>
  </form>`;
  const form = $('#delete-project-form');
  const input = form.elements.confirmation;
  input.addEventListener('input', () => {
    $('[data-delete-project-error]', form).textContent = '';
    updateProjectDeletionForm(form, state.projects.find(p => p.id === id) ?? project);
  });
  form.addEventListener('submit', deleteProject);
  updateProjectDeletionForm(form, project);
  input.focus({preventScroll:true});
}

async function deleteProject(event) {
  event.preventDefault();
  const form = event.target, id = form.dataset.projectId, hash = location.hash;
  const directory = state.data_directory;
  const project = state.projects.find(project => project.id === id);
  const input = form.elements.confirmation;
  const confirmation = input.value;
  if (!project || project.syncing || form.dataset.pending === 'true' || !confirmation || confirmation !== project.name) return;

  const cancel = $('[data-action="cancel-project-deletion"]', form);
  const error = $('[data-delete-project-error]', form);
  form.dataset.pending = 'true';
  input.disabled = cancel.disabled = true;
  error.textContent = '';
  updateProjectDeletionForm(form, project);
  try {
    await invoke('DeleteProject', id, confirmation);
  } catch (err) {
    error.textContent = err.message;
    form.dataset.pending = 'false';
    input.disabled = cancel.disabled = false;
    updateProjectDeletionForm(form, state.projects.find(p => p.id === id) ?? project);
    return;
  }

  if (state.data_directory === directory) {
    if (projectDeleteDraft?.id === id) projectDeleteDraft = null;
    state = {...state, projects:state.projects.filter(project => project.id !== id)};
    if (location.hash === hash) location.hash = 'projects';
    else renderNav();
  }
  toast(t('deleted'));
}

function configureGitHubToken(form) {
  if ($('button[type="submit"]', form).disabled) return;
  const {projectId, revision} = form.dataset;
  projectTokenSetup = {
    returnHash: location.hash,
    draft: {...projectFormValues(form), id: projectId, revision},
  };
  location.hash = githubTokenSettingsHash;
}

function cancelProject(form) {
  const {projectId} = form.dataset;
  location.hash = projectId ? 'project/' + projectId : newProjectReturnHash || 'projects';
}

async function saveProject(e) {
  e.preventDefault();
  const form = e.target;
  const submit = $('button[type="submit"]', form);
  if (submit.disabled) return;
  const error = $('[data-project-error]', form);
  const {projectId, revision} = form.dataset;
  const body = projectFormValues(form, true);
  const hash = location.hash;
  if (projectId) body.revision = Number(revision);
  error.textContent = '';
  submit.disabled = true;
  try {
    const project = projectId ? await invoke('UpdateProject', projectId, body) : await invoke('CreateProject', body);
    await refresh(false);
    if (location.hash === hash && form.isConnected) {
      projectTab = 'techStack';
      location.hash = 'project/' + project.id;
    } else {
      render();
    }
    toast(t('saved'));
  } catch (err) {
    error.textContent = err.message;
  } finally {
    submit.disabled = false;
  }
}
async function saveSettings(e) {
  e.preventDefault();
  if (changingDataDirectory) return;
  const form = e.target, submit = $('button[type="submit"]', form);
  const tokenSetup = location.hash === githubTokenSettingsHash ? projectTokenSetup : null;
  submit.disabled = true;
  const body = {...state.settings, sources:{}, scanners:{}, tokens:{}, clear_tokens:[...clearing]};
  for (const key of ['language','nvd_url','cve_url','osv_url','ai_provider','openai_model','claude_model']) body[key] = form.elements[key].value.trim();
  for (const key of ['cache_hours','cache_max_entries','cache_max_mib']) body[key] = Number(form.elements[key].value);
  for (const key of ['nvd','cve','osv']) body.sources[key] = form.elements['source_'+key].checked;
  for (const key of Object.keys(scannerLabels)) body.scanners[key] = form.elements['scanner_'+key].checked;
  for (const key of Object.keys(credentialLabels)) body.tokens[key] = form.elements['token_'+key].value.trim();
  for (const field of $$('.credential-field', form)) setCredentialVisibility(field, false);
  try {
    await invoke('SaveSettings', body);
    for (const key of Object.keys(credentialLabels)) form.elements['token_'+key].value = '';
    await refresh();
    if (body.tokens.github && tokenSetup && projectTokenSetup === tokenSetup && location.hash === githubTokenSettingsHash) {
      location.hash = tokenSetup.returnHash;
    }
    toast(t('saved'));
  } catch (err) {
    const error = $('#settings-error');
    if (error) error.textContent = err.message;
    else toast(err.message, true);
  } finally {
    submit.disabled = false;
  }
}
async function scanProjectCode(id) {
  const project = state.projects.find(project => project.id === id);
  if (!project?.scan_code || (!project.local_path && !projectRepositories(project).length)) {
    throw new Error(t('codeScanProjectSetup'));
  }
  if (!Object.values(state.settings.scanners || {}).some(Boolean)) {
    throw new Error(t('codeScanConfigurationSetup'));
  }
  await invoke('ScanCode', id);
  await refresh();
  toast(t('codeScanStarted'));
}
async function syncProject(id,assetID='',mode='auto',severity=''){const options=assetID?{asset_id:assetID}:{};if(mode!=='auto')options.mode=mode;if(severity)options.severity=severity;await invoke('Sync',id,options);await refresh();toast(t('syncStarted'));}
async function sample(){const p=await invoke('CreateProject',{name:'Sample · Java service',description:t('sampleDescription'),repository:'',local_path:'',scan_code:false,schedule:'off',assets:[{id:'',kind:'library',name:'org.apache.logging.log4j:log4j-core',version:'2.14.1',ecosystem:'Maven',cpe:'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'}]});await refresh(false);location.hash='project/'+p.id;projectTab='techStack';render();toast(t('sampleAdded'));}
function showFinding(id,asset,project){
  const p = state.projects.find(p => p.id === project);
  const finding = p?.findings?.find(f => f.id === id && f.asset_id === asset);
  if (!finding) return;
  const f = {...finding, project_id:p.id, project_name:p.name};
  currentFinding=f;$('#detail-body').innerHTML=`<div class="detail-tags">${pill(t(severityKey(f.severity)),severityKey(f.severity))}${pill(f.id)}${pill(t(f.match),f.match==='review'?'review':'')}${f.score?pill(t('score')+' '+f.score):''}</div><h2 class="detail-title">${esc(f.title||f.id)}</h2><p class="subtitle">${esc(f.component)} ${esc(findingVersionLabel(f))} · ${esc(f.project_name)} · ${esc(f.sources.join(' + '))}</p>${f.match==='review'?`<div class="notice">${t('reviewWarning')}</div>`:f.match==='cpe'?`<div class="notice info">${t('cpeWarning')}</div>`:''}<p class="detail-description">${esc(f.description)}</p><div class="detail-section"><h3>${t('remediation')}</h3><div id="advice-result"></div><div class="advice-actions"><select id="advice-provider" aria-label="${t('defaultProvider')}">${providerOptions(state.settings.ai_provider)}</select><button class="button primary small" data-action="advice">${t('getAdvice')}</button></div><p class="form-note">${t('aiDisclosure')}</p></div><div class="detail-section"><h3>${t('references')}</h3><ul class="reference-list">${f.references?.length?f.references.map(u=>safeURL(u)?`<li><a href="${safeURL(u)}" target="_blank" rel="noreferrer">${esc(u)} ↗</a></li>`:'').join(''):`<li class="muted">${t('noReferences')}</li>`}</ul></div>`;$('#detail-dialog').showModal();getAdvice('public');}
async function getAdvice(provider){const f=currentFinding,container=$('#advice-result');container.innerHTML=`<div class="advice-box"><p>${t('generating')}</p></div>`;const btn=$('[data-action="advice"]');if(btn)btn.disabled=true;try{const a=await invoke('Advice',f.project_id,{finding_id:f.id,asset_id:f.asset_id,provider});if(currentFinding!==f)return;container.innerHTML=`<div class="advice-box"><h3>${t(a.provider)}</h3><p>${esc(a.text)}</p>${a.warning?`<p class="form-error">${esc(a.warning)}</p>`:''}${a.provider!=='public'?`<p class="form-note">${t('aiReview')}</p>`:''}</div>`;}catch(err){container.innerHTML=`<p class="form-error">${esc(err.message)}</p>`;}finally{if(btn)btn.disabled=false;}}
document.addEventListener('click',async e=>{if(changingDataDirectory)return;const pageButton=e.target.closest('[data-finding-page]');if(pageButton){if(!pageButton.disabled)turnFindingPage(pageButton.dataset.findingPage);return;}const close=e.target.closest('.close-dialog');if(close){close.closest('dialog').close();return;}if(e.target.closest('.asset-remove')){e.target.closest('.asset-field').remove();return;}const clear=e.target.closest('[data-clear-token]');if(clear){clearCredential(clear);return;}const dismiss=e.target.closest('[data-dismiss-workflow]');if(dismiss){dismissWorkflow(dismiss.dataset.projectId,dismiss.dataset.dismissWorkflow);return;}const toggle=e.target.closest('[data-toggle-workflow]');if(toggle){toggleWorkflow(toggle.dataset.toggleWorkflow);return;}const tab=e.target.closest('[data-tab]');if(tab){if(projectTab!==tab.dataset.tab)expandedRuns.clear();projectTab=tab.dataset.tab;render();return;}const row=e.target.closest('[data-finding]');if(row){showFinding(row.dataset.finding,row.dataset.asset,row.dataset.project);return;}const target=e.target.closest('[data-action]');if(!target)return;try{switch(target.dataset.action){case'new-project':openNewProject();break;case'edit-project':location.hash='project/'+target.dataset.id+'/edit';break;case'cancel-project':cancelProject(target.closest('form'));break;case'add-project-asset':{const asset=componentFields();$('[data-project-assets]',target.closest('form')).append(asset);$('[data-field="name"]',asset).focus();break;}case'add-component':openComponent(target.dataset.id);break;case'scan-code':target.disabled=true;await scanProjectCode(target.dataset.id);break;case'sync':target.disabled=true;await syncProject(target.dataset.id,$('#sync-asset')?.value||'', $('#sync-mode')?.value||'auto',$('#sync-severity')?.value||'');break;case'sync-asset':target.disabled=true;await syncProject(target.dataset.id,target.dataset.asset,'auto',componentSyncSeveritySelection.get(stackKey(target.dataset.id,target.dataset.asset))||'');break;case'sync-all':{const severity=syncAllSeverity;target.disabled=true;for(const p of state.projects)if(!p.syncing)await invoke('Sync',p.id,severity?{severity}:{});await refresh();toast(t('syncStarted'));break;}case'sample':target.disabled=true;await sample();break;case'delete-project':openProjectDeletion(target.dataset.id);break;
case'cancel-project-deletion':location.hash='project/'+target.closest('form').dataset.projectId+'/edit';break;
case'control-sync':target.disabled=true;try{await controlWorkflow(target.dataset.id,target.dataset.run,target.dataset.control);}finally{target.disabled=false;}break;case'delete-activity':target.disabled=true;try{await deleteActivity(target.dataset.id,target.dataset.run);}finally{target.disabled=false;}break;case'browse-data-directory':await browseFolder($('#data-directory'),'chooseDataDirectory',state.data_directory);break;case'add-repository': {
  const row = repositoryField();
  $('[data-project-repositories]', target.closest('form')).append(row);
  $('[data-repository-url]', row).focus();
  break;
}
case'remove-repository': {
  const row = target.closest('.project-repository');
  const add = $('[data-action="add-repository"]', target.closest('form'));
  row.remove();
  add.focus();
  break;
}
case'configure-github-token':configureGitHubToken(target.closest('form'));break;
case'focus-snyk-token': {
  const token = $('#credential-snyk', target.closest('form'));
  token.scrollIntoView({block:'center'});
  token.focus({preventScroll:true});
  break;
}
case'return-to-project-form':if(projectTokenSetup)location.hash=projectTokenSetup.returnHash;break;
case'toggle-credential':await toggleCredential(target);break;
case'browse-local-repository':await browseFolder(target.closest('form').elements.local_path,'chooseRepositoryFolder');break;case'use-data-directory':{const input=$('#data-directory');if(!input.value.trim()){input.focus();return;}await changeDataDirectory(input.value);break;}case'reset-data-directory':await changeDataDirectory('');break;case'check-scanner':{const input=$('[data-scanner-check="'+target.dataset.scanner+'"]');if(input)await checkScanner(input);break;}case'advice':await getAdvice($('#advice-provider').value);break;}}catch(err){toast(err.message,true);target.disabled=false;}});
document.addEventListener('change',e=>{if(e.target.matches('[data-scanner-check]'))checkScanner(e.target);if(e.target.matches('[data-sync-project]'))syncSelection[e.target.dataset.syncProject]=e.target.value;if(e.target.matches('[data-sync-mode-project]'))syncModeSelection[e.target.dataset.syncModeProject]=e.target.value;if(e.target.matches('[data-sync-severity-project]'))syncSeveritySelection[e.target.dataset.syncSeverityProject]=e.target.value;if(e.target.matches('[data-sync-all-severity]'))syncAllSeverity=e.target.value;if(e.target.matches('[data-sync-component-severity]'))componentSyncSeveritySelection.set(stackKey(e.target.dataset.projectId,e.target.dataset.assetId),e.target.value);});
document.addEventListener('input', e => {
  const input = e.target;
  if (!input.matches('[data-credential-input]')) return;
  input.placeholder = '';
  const field = input.closest('.credential-field');
  field.classList.remove('credential-preview-selected');
  const remove = $('[data-clear-token]', field);
  if (input.value.trim() && clearing.delete(remove.dataset.clearToken)) remove.textContent = t('clear');
  if (input.type === 'text' && input.value) return;
  if ($('[data-credential-toggle]', field).getAttribute('aria-pressed') === 'true') setCredentialVisibility(field, false);
});
function deselectCredentialPreview(event) {
  event.target.closest('.credential-field')?.classList.remove('credential-preview-selected');
}
document.addEventListener('focusout', deselectCredentialPreview);
document.addEventListener('pointerdown', deselectCredentialPreview);
document.addEventListener('keydown',e=>{if(handleCredentialKeydown(e))return;if(e.key==='Enter'&&e.target.id==='data-directory'){e.preventDefault();$('[data-action="use-data-directory"]')?.click();return;}if((e.key==='Enter'||e.key===' ')&&e.target.matches('[data-finding]')){e.preventDefault();e.target.click();}});
window.addEventListener('vulman-select-all', () => {
  const shortcut = new KeyboardEvent('keydown', {key:'a', metaKey:true, bubbles:true, cancelable:true});
  if (document.activeElement?.dispatchEvent(shortcut)) document.execCommand('selectAll');
});
$('#component-form').addEventListener('submit',saveComponent);$('#help-button').addEventListener('click',()=>$('#about-dialog').showModal());
$('#language-select').addEventListener('change',async e=>{const select=e.target;if(!state||changingDataDirectory||select.value===lang)return;select.disabled=true;try{await invoke('SaveSettings',{...state.settings,language:select.value});await refresh();}catch(err){select.value=lang;toast(err.message,true);}finally{select.disabled=false;}});
$('#confirm-action').addEventListener('click', () => $('#confirm-dialog').close('confirm'));
const followExternalLink = async event => {
  if (event.type === 'auxclick' && event.button !== 1) return;
  const link = event.target.closest('a[target="_blank"]');
  if (!link) return;
  event.preventDefault();
  try {
    await invoke('OpenExternal', link.href);
  } catch (err) {
    toast(err.message, true);
  }
};
document.addEventListener('click', followExternalLink, true);
document.addEventListener('auxclick', followExternalLink, true);
// Dropped links and files must not navigate the privileged WebView.
document.addEventListener('drop', event => event.preventDefault(), true);
function renderNavigation() {
  if (pendingPageRender) cancelAnimationFrame(pendingPageRender);
  pendingPageRender = 0;

  const [page, severity] = route();
  if (page === 'vulnerabilities') filter.severity = findingSeverities.includes(severity) ? severity : '';
  if (page && page !== 'overview' && page !== 'vulnerabilities') {
    render();
    if (location.hash === githubTokenSettingsHash) {
      const token = $('#settings-form input[name="token_github"]');
      token?.scrollIntoView({block:'center'});
      token?.focus({preventScroll:true});
    } else {
      window.scrollTo(0, 0);
    }
    return;
  }

  const hash = location.hash;
  renderNav();
  $('#main').innerHTML = `<p class="loading" role="status">${esc(t('renderingPage'))}</p>`;
  window.scrollTo(0, 0);

  // Let the WebView paint the loading message before generating the page.
  pendingPageRender = requestAnimationFrame(() => {
    pendingPageRender = requestAnimationFrame(() => {
      pendingPageRender = 0;
      if (location.hash !== hash) return;
      try {
        render();
      } catch (err) {
        showPageError(err);
      }
    });
  });
}
function showPageError(err) {
  const title = Object.hasOwn(localizations, defaultLanguage) ? t('errorTitle') : 'Vulman';
  $('#main').innerHTML = `<div class="error-page"><h1>${esc(title)}</h1><p>${esc(err.message)}</p></div>`;
}

history.scrollRestoration = 'manual';
window.addEventListener('hashchange', () => {
  expandedRuns.clear();
  filter = {search:'', severity:'', project:'', match:'', stack:''};
  const [page, id, view] = route();
  const editor = $('#project-editor form');
  if (page !== 'project' || (view !== 'edit' && editor?.dataset?.projectId !== id)) projectTab = 'vulnerabilities';
  findingsPage = 1;
  const returning = projectTokenSetup?.returnHash === location.hash ? projectTokenSetup.draft : null;
  if (location.hash !== newProjectHash &&
      (location.hash !== githubTokenSettingsHash || projectTokenSetup?.returnHash !== newProjectHash)) {
    newProjectReturnHash = '';
  }
  if (page !== 'project' || (view !== 'edit' && view !== 'delete') || projectDeleteDraft?.id !== id) projectDeleteDraft = null;
  if (state) renderNavigation();
  if (location.hash !== githubTokenSettingsHash) projectTokenSetup = null;
  if (returning) {
    const container = $('#project-editor');
    if (container) $('[data-action="configure-github-token"]', container)?.focus();
  }
});
async function pollState() {
  if (!state || changingDataDirectory || pollPending || pendingPageRender || document.hidden || $('dialog[open]')) return;
  pollPending = true;
  const current = state;
  try {
    const next = await invoke('StateSince', current.version);
    if (!changingDataDirectory && state === current) applyPollingState(next);
  } catch {
    toast(t('connectionLost'), true, 'connection-lost');
  } finally {
    pollPending = false;
  }
}
async function boot() {
  try {
    localizations = await invoke('Localizations');
    const select = $('#language-select');
    select.innerHTML = languageOptions();
    await refresh(false);
    select.disabled = false;
    renderNavigation();
    if (state.storage_warning) toast(t(state.storage_warning), true);
    setInterval(pollState, 2000);
  } catch (err) {
    showPageError(err);
  }
}
boot();
