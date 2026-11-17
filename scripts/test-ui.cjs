// Optional UI behavior tests: node --test scripts/test-ui.cjs (no npm install).
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const localesPath = path.join(__dirname, '../cmd/vulman/locales');
const bundledLocalizations = Object.fromEntries(
  fs.readdirSync(localesPath).filter(name => name.endsWith('.json')).map(name => [
    path.basename(name, '.json'), JSON.parse(fs.readFileSync(path.join(localesPath, name), 'utf8')),
  ]),
);

function app(byName) {
  const elements = new Map();
  const document = {
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, {listeners:{}, addEventListener(type,callback) {this.listeners[type]=callback;}, insertAdjacentHTML(position,html) {this.insertedHTML=html;}, innerHTML:''});
      return elements.get(selector);
    },
    querySelectorAll() {return [];},
    listeners:{},
    addEventListener(type,callback,capture) {if (!capture) this.listeners[type]=callback;}
  };
  const window = {listeners:{}, scrollTo() {}, addEventListener(type,callback) {this.listeners[type]=callback;}};
  const frames = new Map();
  let nextFrame = 0;
  const context = vm.createContext({
    document, window, history:{scrollRestoration:'auto'}, location:{hash:'#project/p'}, URL, Call:{ByName:byName}, bundledLocalizations,
    requestAnimationFrame(callback) {const id = ++nextFrame; frames.set(id, callback); return id;},
    cancelAnimationFrame(id) {frames.delete(id);},
    paintFrame() {const callbacks = [...frames.values()]; frames.clear(); callbacks.forEach(callback => callback());},
  });
  const source = fs.readFileSync(path.join(__dirname,'../cmd/vulman/ui/app.js'),'utf8').replace(/^import .*$/m, '').replace(/boot\(\);\s*$/, '');
  vm.runInContext(source,context);
  vm.runInContext('localizations = bundledLocalizations', context);
  return expression => vm.runInContext(expression,context);
}

test('desktop boots the full workspace through its native bridge', async () => {
  const requests = [];
  const run = app(async (...args) => {
    requests.push(args);
    if (args[0] === 'main.Desktop.Localizations') return bundledLocalizations;
    return {projects:[], settings:{language:'en'}};
  });
  run("location.hash = '#projects'; localize = () => {}; setInterval = () => {}; fetch = () => {throw new Error('unexpected browser fetch');};");
  await run('boot()');
  assert.deepEqual(requests,[['main.Desktop.Localizations'], ['main.Desktop.State']]);
  assert.match(run("document.querySelector('#main').innerHTML"),/data-action="new-project"/);
  assert.match(run("document.querySelector('#nav').innerHTML"),/href="#settings"/);
  assert.match(run("document.querySelector('#nav').innerHTML"),/href="#vulnerabilities"/);
});

test('bundled languages populate both selectors and missing translations use English', async () => {
  const localizations = {
    ...bundledLocalizations,
    'pt-BR': {name:'Português', messages:{projects:'Projetos'}},
  };
  let language = 'ja';
  const run = app(async (method, settings) => {
    if (method === 'main.Desktop.Localizations') return localizations;
    if (method === 'main.Desktop.SaveSettings') language = settings.language;
    if (method === 'main.Desktop.State') {
      return {projects:[], settings:{language, sources:{}, scanners:{}}, token_status:{}};
    }
  });
  run(`
    location.hash = '#settings';
    document.documentElement = {};
    $('#language-select').setAttribute = () => {};
    setInterval = () => {};
  `);
  await run('boot()');
  assert.equal(run('document.documentElement.lang'), 'ja');
  assert.equal(run(`$('#language-select').value`), 'ja');
  assert.match(run(`$('#language-select').innerHTML`), /value="pt-BR" lang="pt-BR" >Português/);
  assert.match(run(`$('#main').innerHTML`), /<select name="language">[^]*?value="ja" lang="ja" selected>日本語/);
  assert.match(run(`$('#main').innerHTML`), /value="pt-BR" lang="pt-BR" >Português/);

  await run(`
    const selector = $('#language-select');
    selector.value = 'pt-BR';
    selector.listeners.change({target:selector});
  `);
  assert.equal(language, 'pt-BR');
  assert.equal(run('document.documentElement.lang'), 'pt-BR');
  assert.equal(run("t('projects')"), 'Projetos');
  assert.equal(run("t('overview')"), 'Overview');
  assert.equal(run('formatResultNumber(1001)'), '1.001');

  language = 'unavailable';
  await run('refresh()');
  assert.equal(run('document.documentElement.lang'), 'en');
});

test('switching pages resets the scroll while polling leaves it alone', () => {
  const run = app();
  run(`
    state = {projects:[], settings:{language:'en'}};
    var events = [];
    render = () => events.push(['render', location.hash]);
    window.scrollTo = (x, y) => events.push(['scroll', x, y]);
    localize = () => {};
    location.hash = '#vulnerabilities'; window.listeners.hashchange(); paintFrame(); paintFrame();
    location.hash = '#overview'; window.listeners.hashchange(); paintFrame(); paintFrame();
    location.hash = '#projects'; window.listeners.hashchange();
    applyPollingState({...state, projects:[{id:'p', assets:[], findings:[]}]});
  `);
  assert.equal(run('history.scrollRestoration'), 'manual');
  assert.deepEqual(JSON.parse(run('JSON.stringify(events)')), [
    ['scroll', 0, 0], ['render', '#vulnerabilities'],
    ['scroll', 0, 0], ['render', '#overview'],
    ['render', '#projects'], ['scroll', 0, 0],
    ['render', '#projects'],
  ]);
});

test('Overview and Vulnerabilities show a localized loading message before rendering', () => {
  const run = app();
  run(`state = {projects:[], settings:{language:'en', sources:{}}};
    location.hash = '#overview'; window.listeners.hashchange();`);
  const main = () => run(`document.querySelector('#main').innerHTML`);
  assert.match(main(), /role="status">Rendering, please wait\./);
  run(`paintFrame(); render();`);
  assert.match(main(), /Rendering, please wait\./);
  run(`paintFrame();`);
  assert.match(main(), /Security overview/);
  assert.doesNotMatch(main(), /Rendering, please wait\./);
  run(`lang = 'ja'; location.hash = '#vulnerabilities'; window.listeners.hashchange();`);
  assert.match(main(), /画面を表示しています。しばらくお待ちください。/);
  run(`paintFrame(); paintFrame();`);
  assert.match(main(), /id="finding-results"/);
});

test('leaving a loading page cancels its render', () => {
  const run = app();
  run(`state = {projects:[], settings:{language:'en', sources:{}}};
    location.hash = '#vulnerabilities'; window.listeners.hashchange(); paintFrame();
    location.hash = '#projects'; window.listeners.hashchange();
    var projectsPage = document.querySelector('#main').innerHTML;
    render = () => {throw new Error('stale page rendered');};
    paintFrame();`);
  assert.match(run('projectsPage'), /Your projects/);
  assert.equal(run(`document.querySelector('#main').innerHTML`), run('projectsPage'));
});

test('Overview severity rows open the workspace findings with the matching severity filter', () => {
  const run = app();
  inventory(run);
  run(`state.settings = {language:'en', sources:{}};
    state.projects[0].findings.push({...state.projects[0].findings[0], id:'CVE-unrated', severity:'UNKNOWN'});
    location.hash = '#overview'; renderOverview();`);
  const main = () => run(`$('#main').innerHTML`);
  const rows = [...main().matchAll(/<a class="severity-row" href="([^"]+)"><span class="severity-label">([^<]+)<\/span>[^]*?<strong>(\d+)<\/strong><\/a>/g)];
  assert.deepEqual(rows.map(row => row.slice(1)), [
    ['#vulnerabilities/CRITICAL', 'Critical', '0'], ['#vulnerabilities/HIGH', 'High', '3'],
    ['#vulnerabilities/MEDIUM', 'Medium', '1'], ['#vulnerabilities/LOW', 'Low', '1'],
    ['#vulnerabilities/UNKNOWN', 'Unrated', '1'],
  ]);
  const navigate = hash => run(`location.hash = ${JSON.stringify(hash)}; window.listeners.hashchange(); paintFrame(); paintFrame();`);
  run(`filter = {search:'old search', severity:'CRITICAL', project:'q', match:'review', stack:'old stack'}; findingsPage = 3;`);
  navigate(rows[1][1]);
  assert.match(main(), /id="severity-filter"[^]*?<option value="HIGH" selected>High<\/option>/);
  assert.deepEqual(findingIDs(main()).sort(), ['CVE-A', 'CVE-CODE', 'CVE-Q']);
  assert.match(main(), /Showing 3 matches \(6 total\)/);
  assert.equal(run('findingsPage'), 1);
  navigate(rows[4][1]);
  assert.match(main(), /<option value="UNKNOWN" selected>Unrated<\/option>/);
  assert.deepEqual(findingIDs(main()), ['CVE-unrated']);
  navigate('#vulnerabilities');
  assert.equal(findingIDs(main()).length, 6);
  navigate('#vulnerabilities/invalid');
  assert.equal(run('filter.severity'), '');
});

test('vulnerability pages render at most 100 findings and filter the entire sorted result set', async () => {
  const run = app();
  run(`
    location.hash = '#vulnerabilities';
    const findings = Array.from({length: 225}, (_, i) => ({id:'CVE-'+i, title:i >= 100 ? 'Match me' : 'First results', component:'Example', asset_id:'a', severity:i === 224 ? 'CRITICAL' : 'HIGH', match:'cpe', sources:['NVD']}));
    state = {projects:[{id:'p', name:'Example', findings}, {id:'q', name:'Other', findings:[{...findings[0], id:'CVE-other'}]}], settings:{language:'en'}};
    const results = document.querySelector('#finding-results');
    results.querySelector = () => null;
    results.innerHTML = findingsTable();
    const next = {dataset:{findingPage:'next'}, closest:selector=>selector==='[data-finding-page]'?next:null};
  `);
  const html = () => run('results.innerHTML');
  assert.equal(findingIDs(html()).length, 100);
  assert.equal(findingIDs(html())[0], 'CVE-224');
  assert.match(html(), /Showing 1–100 of 226 vulnerabilities/);
  assert.match(html(), /Page 1 of 3/);
  await run('document.listeners.click({target:next})');
  assert.match(html(), /Showing 101–200 of 226 vulnerabilities/);
  assert.equal(findingIDs(html()).length, 100);
  await run('document.listeners.click({target:next})');
  assert.match(html(), /Showing 201–226 of 226 vulnerabilities/);
  assert.equal(findingIDs(html()).length, 26);
  run(`bindFilters(); document.querySelector('#finding-search').listeners.input({target:{value:'match me'}});`);
  assert.match(html(), /Showing 1–100 of 125 matches \(226 total\)/);
  assert.equal(findingIDs(html())[0], 'CVE-224');
  assert.equal(run('findingsPage'), 1);
  assert.match(run(`findingsTable('p')`), /Showing 1–100 of 125 matches \(225 total\)/);
  run(`findingsPage = 9; state.projects[0].findings = findings.slice(0, 6); results.innerHTML = findingsTable('p');`);
  assert.equal(run('findingsPage'), 1);
  assert.match(html(), /Showing 0 matches \(6 total\)/);
});

test('idle polling sends the last version and keeps findings when cache metrics change', async () => {
  const calls = [];
  const run = app(async (...args) => {
    calls.push(args);
    return {version:'4', cache_stats:{hits:12}};
  });
  run(`
    location.hash = '#settings';
    document.querySelector = () => null;
    state = {version:'4', projects:[{id:'p'}], settings:{language:'en'}, cache_stats:{hits:10}};
    var lastHits; updateCacheMetrics = stats => {lastHits = stats.hits;};
    render = () => {throw new Error('unchanged workspace was rendered again');};
  `);
  await run('pollState()');
  assert.deepEqual(calls, [['main.Desktop.StateSince','4']]);
  assert.equal(run('lastHits'), 12);
  assert.equal(run('state.projects[0].id'), 'p');
  assert.equal(run('state.settings.language'), 'en');
});

test('configuration switches the data directory and shows a fallback warning', async () => {
  const requests = [];
  const run = app(async (...args) => {
    requests.push(args);
    if (args[0] === 'main.Desktop.State') {
      return {projects:[], settings:{language:'en'}, data_directory:'/default', default_data_directory:'/default',
        storage_warning:'dataDirectoryEmpty', storage_paths:{database:'/default/vulman.db', key:'/default/vulman.key'}};
    }
  });
  run(`
    location.hash = '#settings';
    state = {data_directory:'/alternate', default_data_directory:'/default'};
    const form = $('#settings-form');
    form.querySelector = () => null;
    form.querySelectorAll = () => [];
    localize = () => {};
    render = () => {$('#main').innerHTML = storageDirectoryHTML() + storagePathsHTML();};
    var warningShown;
    toast = (message, warning) => {warningShown = warning ? message : '';};
  `);
  assert.match(run('storageDirectoryHTML()'), /Use default/);
  await run(`changeDataDirectory('/empty')`);
  assert.deepEqual(requests, [['main.Desktop.ChangeDataDirectory','/empty'], ['main.Desktop.State']]);
  const html = run(`$('#main').innerHTML`);
  assert.match(html, /value="\/default"/);
  assert.match(html, /empty or missing/);
  assert.match(html, /\/default\/vulman\.db/);
  assert.match(run('warningShown'), /using the default data directory/);
});

test('project folder browsing fills the path and keeps it when the dialog is cancelled', async () => {
  const requests = [];
  const selected = ['/work/my project', ''];
  const run = app(async (...args) => {requests.push(args); return selected.shift();});
  run(`
    const folder = {value:'/work', isConnected:true};
    const form = {elements:{local_path:folder}};
    const browse = {dataset:{action:'browse-local-repository'}, closest:selector => ({'[data-action]':browse, form})[selector]};
  `);
  await run(`document.listeners.click({target:browse})`);
  assert.equal(run('folder.value'), '/work/my project');
  await run(`document.listeners.click({target:browse})`);
  assert.equal(run('folder.value'), '/work/my project');
  assert.deepEqual(requests, [
    ['main.Desktop.ChooseFolder','Choose a local repository folder','/work'],
    ['main.Desktop.ChooseFolder','Choose a local repository folder','/work/my project'],
  ]);
});

test('scanner results use the reported OS and distinguish unavailable and denied tools', () => {
  const run = app();
  const win = run(`scannerResultHTML('composer',{platform:'windows',status:'missing'})`);
  assert.match(win,/Composer-Setup\.exe/);
  assert.doesNotMatch(win,/brew install|sudo apt/);
  const debian = run(`scannerResultHTML('trivy',{platform:'debian',status:'missing'})`);
  assert.match(debian,/signed package repository/);
  assert.match(debian,/apt-get install trivy/);
  assert.doesNotMatch(debian,/brew install|trivy\.exe/);
  const pip = run(`scannerSettingsHTML({'pip-audit':true})`);
  assert.match(pip,/name="scanner_pip-audit" checked data-scanner-check="pip-audit"/);
  assert.match(run(`scannerResultHTML('pip-audit',{platform:'darwin',status:'missing'})`),/brew install pip-audit/);
  assert.match(run(`lang='ja'; scannerResultHTML('pip-audit',{platform:'windows',status:'missing'})`),/pipx install pip-audit/);
  run(`lang='en'`);
  const denied = run(`scannerResultHTML('npm',{platform:'darwin',status:'permission',path:'/tmp/<bin>/npm'})`);
  assert.match(denied,/denied permission/);
  assert.match(denied,/Privacy & Security/);
  assert.match(denied,/\/tmp\/&lt;bin&gt;\/npm/);
  assert.doesNotMatch(denied,/Read & execute|brew install/);
});

test('selecting a scanner probes it and unchecking clears the result', async () => {
  const calls = [];
  const run = app(async (...args) => {
    calls.push(args);
    return {platform:'darwin',status:'ready',path:'/usr/local/bin/trivy'};
  });
  run(`
    const panel = $('#scanner-status-trivy');
    Object.assign(panel, {dataset:{}, isConnected:true});
    const scanner = {dataset:{scannerCheck:'trivy'}, checked:true};
    var checking = checkScanner(scanner);
  `);
  assert.match(run('panel.textContent'), /Checking availability/);
  await run('checking');
  assert.deepEqual(calls,[['main.Desktop.CheckScanner','trivy']]);
  assert.match(run('panel.innerHTML'), /Vulman can run this tool/);
  run('scanner.checked = false; checkScanner(scanner)');
  assert.equal(run('panel.hidden'), true);
  assert.equal(run('panel.textContent'), '');
});

test('Snyk setup is visible before enabling the scanner and links to its credential without leaving Configuration', async () => {
  const run = app();
  const setup = run('scannerSettingsHTML({})');
  assert.match(setup, /name="scanner_snyk"\s+data-scanner-check="snyk"/);
  assert.match(setup, /API credentials → Snyk token/);
  assert.match(setup, /Run configured code scanners.*Scan code/);
  assert.match(setup, /authenticate-to-use-the-cli/);
  assert.match(run(`scannerResultHTML('snyk',{platform:'darwin',status:'missing'})`), /brew install snyk\/tap\/snyk/);
  assert.match(run(`scannerResultHTML('snyk',{platform:'windows',status:'missing'})`), /snyk\.exe/);
  assert.match(run(`scannerResultHTML('snyk',{platform:'debian',status:'missing'})`), /standalone Linux CLI/);
  assert.match(run(`scannerResultHTML('snyk',{status:'ready'})`), /checks the token during a scan/);
  run(`lang='ja'; state={token_status:{}}; location.hash='#settings';`);
  assert.match(run('scannerSettingsHTML({})'), /Snyk トークン欄へ移動/);
  const credentials = run('credentialSettingsHTML()');
  assert.match(credentials, /id="credential-snyk"[^>]*aria-describedby="credential-snyk-hint"/);
  assert.match(credentials, /SNYK_TOKEN として Snyk CLI に渡します/);
  await run(`
    var calls = [];
    const input = {value:'draft', scrollIntoView(){ calls.push('scroll'); }, focus(){ calls.push('focus'); }};
    const form = {querySelector(selector){ return selector === '#credential-snyk' ? input : null; }};
    const snykButton = {dataset:{action:'focus-snyk-token'}, closest(selector){ return selector === 'form' ? form : null; }};
    document.listeners.click({target:{closest:selector => selector === '[data-action]' ? snykButton : null}});
  `);
  assert.equal(run("calls.join(',')"), 'scroll,focus');
  assert.equal(run('location.hash'), '#settings');
  assert.equal(run('input.value'), 'draft');
});

test('sync defaults to everything and keeps a selected component on redraw', () => {
  const run = app();
  run(`var p={id:'p',assets:[{id:'a',kind:'database',name:'PostgreSQL',version:'16'}]};`);
  let html = run('syncControls(p)');
  assert.match(html, /<option value="">Everything<\/option>/);
  assert.doesNotMatch(html.match(/<select id="sync-asset"[\s\S]*?<\/select>/)[0], / selected/);
  assert.match(html, /Database · PostgreSQL 16/);
  run(`syncSelection.p='a'`);
  assert.match(run('syncControls(p)'), /value="a" selected/);
  run('p.assets=[]');
  assert.doesNotMatch(run('syncControls(p)').match(/<select id="sync-asset"[\s\S]*?<\/select>/)[0], / selected/);
});

test('sync selection is localized and component names are escaped', () => {
  const run=app();
  const html=run(`lang='ja';syncControls({id:'p',assets:[{id:'a',kind:'library',name:'<script>',version:'1'}]})`);
  assert.match(html,/技術スタック別の同期/);
  assert.match(html,/すべて/);
  assert.match(html,/&lt;script&gt;/);
  assert.doesNotMatch(html,/<script>/);
});

test('sync requests distinguish everything from one component',async()=>{
  const run=app();
  run(`var calls=[];invoke=async(...args)=>calls.push(args);refresh=async()=>{};toast=()=>{};`);
  await run(`syncProject('p')`);
  await run(`syncProject('p','a')`);
  assert.deepEqual(JSON.parse(run('JSON.stringify(calls)')), [
    ['Sync','p',{}],
    ['Sync','p',{asset_id:'a'}]
  ]);
});

test('successful component sync does not mark a project fully assessed',()=>{
  const run=app();workflowFixture(run);
  run(`
    Object.assign(workflow, {asset_id:'a', asset_name:'Go 1.26.3', status:'complete'});
    workflow.steps.forEach(step => step.status='complete');
    const scopedProject = {...project, assets:[], findings:[], schedule:'off', revision:1, assessed_revision:0, runs:[workflow]};
    state = {projects:[scopedProject]};
    renderProject('p');
  `);
  const html=run(`$('#main').innerHTML`);
  assert.match(html,/class="project-meta"><span class="pill ">Full-project assessment needed<\/span>/);
  assert.match(html,/class="workflow-actions"><span class="pill complete">Complete<\/span>/);
  run(`lang='ja'`);
  assert.match(run(`projectStatus(scopedProject)`),/プロジェクト全体の評価が必要/);
  run(`lang='en'; scopedProject.last_sync='2026-01-01'; scopedProject.assessed_revision=1`);
  assert.match(run(`projectStatus(scopedProject)`),/>Complete<\/span>/);
  const failed=run(`projectStatus({revision:1,assessed_revision:1,last_sync:'2026-01-01',runs:[{asset_id:'a',status:'complete'},{status:'partial'}]})`);
  assert.match(failed,/Partial/);
});

function inventory(run) {
  run(`state={projects:[
    {id:'p',name:'Project One',assets:[
      {id:'shared',kind:'library',name:'demo',version:'1'},
      {id:'no-findings',kind:'database',name:'PostgreSQL',version:'16'}
    ],findings:[
      {id:'CVE-A',asset_id:'shared',component:'demo',version:'1',title:'First advisory',severity:'HIGH',match:'package',sources:['OSV']},
      {id:'CVE-M',asset_id:'shared',component:'demo',version:'1',title:'Second advisory',severity:'MEDIUM',match:'review',sources:['NVD']},
      {id:'CVE-CODE',asset_id:'code:indirect',component:'indirect',version:'2',title:'Scanner finding',severity:'HIGH',match:'scanner',sources:['Trivy']},
      {id:'CVE-OLD',asset_id:'retired',component:'retired-library',version:'0.1',title:'Retained advisory',severity:'LOW',match:'review',sources:['NVD']}
    ]},
    {id:'q',name:'Project Two',assets:[{id:'shared',kind:'library',name:'demo',version:'2'}],findings:[
      {id:'CVE-Q',asset_id:'shared',component:'demo',version:'2',title:'Other project',severity:'HIGH',match:'package',sources:['OSV']}
    ]}
  ]};`);
}

const findingIDs = html => [...html.matchAll(/data-finding="([^"]+)"/g)].map(m=>m[1]);

test('both vulnerability views default to all tech stacks with correctly scoped options',()=>{
  const run=app();inventory(run);
  const local=run(`filtersHTML(false,'p')`);
  assert.match(local,/id="tech-stack-filter"/);
  assert.match(local,/<option value="">All tech stacks<\/option>/);
  assert.match(local,/Database · PostgreSQL 16/);
  assert.doesNotMatch(local,/Project Two|demo 2/);
  assert.deepEqual(findingIDs(run(`findingsTable('p')`)).sort(),['CVE-A','CVE-CODE','CVE-M','CVE-OLD']);
  const global=run(`filtersHTML(true)`);
  assert.match(global,/Project One · OSS library · demo 1/);
  assert.match(global,/Project Two · OSS library · demo 2/);
  assert.equal(findingIDs(run(`findingsTable()`)).length,5);
});

test('tech stack filtering isolates the chosen project even with duplicate component IDs',()=>{
  const run=app();inventory(run);
  run(`filter.stack=stackKey('p','shared')`);
  assert.deepEqual(findingIDs(run(`findingsTable('p')`)),['CVE-A','CVE-M']);
  assert.deepEqual(findingIDs(run('findingsTable()')),['CVE-A','CVE-M']);
  assert.match(run('filtersHTML(true)'),/selected/);
  run(`filter.stack=stackKey('q','shared')`);
  assert.deepEqual(findingIDs(run('findingsTable()')),['CVE-Q']);
});

test('tech stack combines with search, severity, and match type and explains empty results',()=>{
  const run=app();inventory(run);
  run(`filter.stack=stackKey('p','shared');filter.search='first';filter.severity='HIGH';filter.match='package'`);
  assert.deepEqual(findingIDs(run(`findingsTable('p')`)),['CVE-A']);
  run(`filter.severity='LOW'`);
  assert.match(run(`findingsTable('p')`),/No findings match these filters/);
  run(`filter={search:'',severity:'',project:'',match:'',stack:stackKey('p','no-findings')}`);
  assert.match(run(`findingsTable('p')`),/No findings match these filters/);
});

test('changing project narrows the stack options and clears incompatible selections',()=>{
  const run=app();inventory(run);
  run(`filter.stack=stackKey('p','shared');bindFilters();document.querySelector('#project-filter').listeners.change({target:{value:'q'}})`);
  assert.equal(run('filter.stack'),'');
  const options=run(`document.querySelector('#tech-stack-filter').innerHTML`);
  assert.match(options,/Project Two · OSS library · demo 2/);
  assert.doesNotMatch(options,/Project One|PostgreSQL/);
  assert.deepEqual(findingIDs(run(`document.querySelector('#finding-results').innerHTML`)),['CVE-Q']);
  run(`document.querySelector('#tech-stack-filter').listeners.change({target:{value:stackKey('q','shared')}})`);
  assert.equal(run('filter.stack'),run(`stackKey('q','shared')`));
});

test('scanner components and removed inventory remain filterable',()=>{
  const run=app();inventory(run);
  const options=run(`techStackFilterHTML('p')`);
  assert.match(options,/Code scanner · indirect 2/);
  assert.match(options,/Previous inventory · retired-library 0.1/);
  run(`filter.stack=stackKey('p','code:indirect')`);
  assert.deepEqual(findingIDs(run(`findingsTable('p')`)),['CVE-CODE']);
  run(`filter.stack=stackKey('p','retired')`);
  assert.deepEqual(findingIDs(run(`findingsTable('p')`)),['CVE-OLD']);
});

test('stack filters localize labels and escape component and project names',()=>{
  const run=app();inventory(run);
  run(`lang='ja';state.projects[0].name='<script>';state.projects[0].assets[0].name='"<img>'`);
  const html=run('techStackFilterHTML()');
  assert.match(html,/すべての技術スタック/);
  assert.match(html,/aria-label="技術スタック"/);
  assert.match(html,/&lt;script&gt;/);
  assert.match(html,/&quot;&lt;img&gt;/);
  assert.doesNotMatch(html,/<script>|<img>/);
});

test('result counts use project totals in its tab and all-project totals in the global view',()=>{
  const run=app();inventory(run);
  assert.match(run(`findingsTable('p')`),/Showing 4 of 4 vulnerabilities/);
  assert.match(run('findingsTable()'),/Showing 5 of 5 vulnerabilities/);
  run(`filter.stack=stackKey('p','shared')`);
  assert.match(run(`findingsTable('p')`),/Showing 2 matches \(4 total\)/);
  assert.match(run('findingsTable()'),/Showing 2 matches \(5 total\)/);
});

test('counts update on component, severity, search, and match changes including zero matches',()=>{
  const run=app();inventory(run);
  run(`bindFilters('p');document.querySelector('#tech-stack-filter').listeners.change({target:{value:stackKey('p','shared')}})`);
  assert.match(run(`document.querySelector('#finding-results').innerHTML`),/Showing 2 matches \(4 total\)/);
  run(`document.querySelector('#severity-filter').listeners.change({target:{value:'HIGH'}})`);
  assert.match(run(`document.querySelector('#finding-results').innerHTML`),/Showing 1 match \(4 total\)/);
  run(`document.querySelector('#match-filter').listeners.change({target:{value:'review'}})`);
  assert.match(run(`document.querySelector('#finding-results').innerHTML`),/Showing 0 matches \(4 total\)/);
  run(`document.querySelector('#match-filter').listeners.change({target:{value:''}});document.querySelector('#finding-search').listeners.input({target:{value:'no such advisory'}})`);
  const empty=run(`document.querySelector('#finding-results').innerHTML`);
  assert.match(empty,/Showing 0 matches \(4 total\)/);
  assert.match(empty,/No findings match these filters/);
  run(`document.querySelector('#finding-search').listeners.input({target:{value:''}});document.querySelector('#severity-filter').listeners.change({target:{value:''}});document.querySelector('#tech-stack-filter').listeners.change({target:{value:''}})`);
  assert.match(run(`document.querySelector('#finding-results').innerHTML`),/Showing 4 of 4 vulnerabilities/);
});

test('global count retains the workspace total when the project filter changes',()=>{
  const run=app();inventory(run);
  run(`bindFilters();document.querySelector('#project-filter').listeners.change({target:{value:'q'}})`);
  assert.match(run(`document.querySelector('#finding-results').innerHTML`),/Showing 1 match \(5 total\)/);
  run(`document.querySelector('#project-filter').listeners.change({target:{value:''}})`);
  assert.match(run(`document.querySelector('#finding-results').innerHTML`),/Showing 5 of 5 vulnerabilities/);
});

test('result counts handle empty inventories, singular totals, Japanese, and refreshed data',()=>{
  const run=app();inventory(run);
  run(`lang='ja';filter.stack=stackKey('p','shared')`);
  assert.match(run(`findingsTable('p')`),/一致する結果を 2 件表示（全 4 件）/);
  run(`lang='en';filter.stack='';state.projects[0].findings.pop()`);
  assert.match(run(`findingsTable('p')`),/Showing 3 of 3 vulnerabilities/);
  assert.match(run(`findingsTable('q')`),/Showing 1 of 1 vulnerability</);
  run(`state.projects=[]`);
  const empty=run('findingsTable()');
  assert.match(empty,/Showing 0 of 0 vulnerabilities/);
  assert.match(empty,/role="status" aria-live="polite"/);
});

function workflowFixture(run) {
  run(`var project={id:'p',name:'Project One'};var workflow={id:'run-1',status:'running',started_at:new Date().toISOString(),finished_at:'0001-01-01T00:00:00Z',steps:[
    {id:'nvd:a',kind:'nvd',component:'demo 1',status:'running',progress:{phase:'waiting',wait_seconds:6,processed:10,total:20,found:10}},
    {id:'cve',kind:'cve',status:'pending',progress:{phase:'queued'}},
    {id:'save',kind:'save',status:'pending',progress:{phase:'queued'}}
  ],logs:[{at:new Date().toISOString(),step_id:'nvd:a',event:'waiting',detail:'6 s'}]};`);
}

test('Scan code uses its own action and reports a separate workflow and activity entry', async () => {
  const run = app();
  workflowFixture(run);
  run(`
    workflow.mode = 'code';
    workflow.status = 'partial';
    workflow.project_name = project.name;
    workflow.project_id = project.id;
    state = {settings:{scanners:{trivy:true}}, projects:[{...project, scan_code:true, local_path:'/repo', assets:[], findings:[], schedule:'off', runs:[workflow]}]};
    renderProject('p');
    const target = {dataset:{action:'scan-code', id:'p'}, closest:selector => selector === '[data-action]' ? target : null};
    const calls = [];
    invoke = async (...args) => {calls.push(args);};
    refresh = async () => {};
    toast = () => {};
  `);
  const html = run(`$('#main').innerHTML`);
  assert.match(html,/data-action="edit-project" data-id="p"[^>]*><svg[^>]*aria-hidden="true"[^>]*>[^]*?<\/svg>Edit project<\/button>/);
  assert.match(html,/data-action="scan-code" data-id="p"[^>]*><svg[^>]*aria-hidden="true"[^>]*>[^]*?<\/svg>Scan code<\/button>/);
  assert.match(html,/Code scan workflow · Project One/);
  assert.match(html,/data-sync-scope="scoped"/);
  assert.match(html,/The latest code scan is incomplete/);
  assert.match(html,/Full-project assessment needed/);
  assert.match(run(`activityList([workflow])`),/Project One<\/a> · Code scan<\/strong>/);
  await run(`document.listeners.click({target})`);
  assert.deepEqual(JSON.parse(run('JSON.stringify(calls)')),[['ScanCode','p']]);
  run(`lang='ja';renderProject('p')`);
  assert.match(run(`$('#main').innerHTML`),/コードスキャンのワークフロー/);
});

test('compact sync panel shows actual steps, active source, and rate-limit wait',()=>{
  const run=app();workflowFixture(run);
  const html=run('workflowRun(project,workflow)');
  assert.match(html,/Sync workflow · Project One/);
  assert.match(html,/0 of 3 steps finished/);
  assert.match(html,/NIST NVD · demo 1/);
  assert.match(html,/Waiting for API rate limit/);
  assert.match(html,/aria-expanded="false"/);
  assert.match(html,/Show more/);
  assert.doesNotMatch(html,/workflow-stepper/);
  assert.match(html,/<progress max="3" value="0"/);
});

test('completed code scan shows all severity counts in the compact widget and in history', () => {
  const run = app();
  workflowFixture(run);
  run(`
    workflow.mode = 'code';
    workflow.status = 'complete';
    workflow.count = 1002;
    workflow.severity_counts = {CRITICAL:1,HIGH:1000,UNKNOWN:1};
    workflow.project_name = project.name;
    workflow.project_id = project.id;
  `);
  const html = run('workflowRun(project,workflow,true)');
  assert.match(html, /Severity breakdown/);
  assert.match(html, /Critical <strong>1<\/strong>/);
  assert.match(html, /High <strong>1,000<\/strong>/);
  assert.match(html, /Medium <strong>0<\/strong>/);
  assert.match(html, /Low <strong>0<\/strong>/);
  assert.match(html, /Unrated <strong>1<\/strong>/);
  assert.doesNotMatch(html, /workflow-stepper/);
  assert.match(run('activityList([workflow])'), /High <strong>1,000<\/strong>/);
  run(`lang='ja'; workflow.severity_counts = {};`);
  assert.match(run('workflowBody(project,workflow)'), /深刻度の内訳/);
  assert.equal([...run('workflowBody(project,workflow)').matchAll(/<strong>0<\/strong>/g)].length, 5);
  run(`workflow.mode = 'auto';`);
  assert.doesNotMatch(run('workflowBody(project,workflow)'), /workflow-severity/);
  run(`workflow.mode = 'code'; workflow.status = 'partial';`);
  assert.doesNotMatch(run('workflowBody(project,workflow)'), /workflow-severity/);
});

test('older scan widgets use current scanner findings only when they match the latest completed scan', () => {
  const run = app();
  workflowFixture(run);
  run(`
    workflow.mode = 'code';
    workflow.status = 'complete';
    workflow.count = 2;
    project.runs = [workflow];
    project.findings = [{match:'cpe',severity:'CRITICAL'}, {match:'scanner',severity:'HIGH'}, {match:'scanner',severity:'UNKNOWN'}];
  `);
  const html = run('workflowBody(project,workflow)');
  assert.match(html, /Current code findings by severity/);
  assert.match(html, /Critical <strong>0<\/strong>/);
  assert.match(html, /High <strong>1<\/strong>/);
  run(`project.runs.unshift({id:'newer'});`);
  assert.match(run('workflowBody(project,workflow)'), /Severity counts are unavailable/);
  assert.doesNotMatch(run('workflowBody(project,workflow)'), /<strong>0<\/strong>/);
  run(`workflow.count = 0;`);
  assert.equal([...run('workflowBody(project,workflow)').matchAll(/<strong>0<\/strong>/g)].length, 5);
});

test('show more expands vertical steps and timestamped logs and show less shrinks them',()=>{
  const run=app();workflowFixture(run);
  run(`toggleWorkflow('run-1')`);
  let html=run('workflowBody(project,workflow)');
  assert.match(html,/Show less/);
  assert.match(html,/aria-expanded="true"/);
  assert.match(html,/workflow-stepper/);
  assert.match(html,/CVE Program/);
  assert.match(html,/Workflow run logs/);
  assert.match(html,/<time>/);
  run(`workflow.steps[0].progress.phase='page'`);
  assert.match(run('workflowBody(project,workflow)'),/Show less/);
  run(`toggleWorkflow('run-1')`);
  html=run('workflowBody(project,workflow)');
  assert.match(html,/Show more/);
  assert.doesNotMatch(html,/workflow-stepper/);
});

test('workflow details start collapsed after navigating between the project and Activity views', async () => {
  const run = app();
  workflowFixture(run);
  run(`
    workflow.status = 'complete';
    state = {projects:[{...project, assets:[], findings:[], schedule:'off', runs:[workflow]}]};
  `);
  const main = () => run(`$('#main').innerHTML`);
  const expand = () => {
    run(`toggleWorkflow('run-1'); render()`);
    assert.match(main(), /Show less/);
  };
  const expectCollapsed = () => {
    assert.match(main(), /Show more/);
    assert.doesNotMatch(main(), /Show less|Workflow run logs/);
  };
  expand();
  run(`location.hash = '#activity'; window.listeners.hashchange()`);
  expectCollapsed();
  expand();
  run(`location.hash = '#project/p'; window.listeners.hashchange()`);
  expectCollapsed();
  expand();
  run(`const tab = {dataset:{tab:'activity'}, closest:selector => selector === '[data-tab]' ? tab : null}`);
  await run(`document.listeners.click({target:tab})`);
  expectCollapsed();
});

test('workflow logs distinguish configured scanners, findings, errors, and skipped code scans', () => {
  const run = app();
  workflowFixture(run);
  run(`
    workflow.status = 'complete';
    workflow.asset_id = 'a';
    expandedRuns.add('run-1');
  `);
  assert.match(run('workflowBody(project,workflow)'),/Code scanners · Skipped for a component-only sync/);
  run(`
    const at = workflow.started_at;
    workflow.logs.push(
      {at, step_id:'scanner', event:'scanner_configured', detail:'govulncheck,npm,composer,snyk'},
      {at, step_id:'scanner', event:'scanning', detail:'npm'},
      {at, step_id:'scanner', event:'scanner_completed', detail:'npm', findings:0},
      {at, step_id:'scanner', event:'scanner_completed', detail:'govulncheck', findings:1},
      {at, step_id:'scanner', event:'scanner_failed', detail:'composer · <failed>'},
      {at, step_id:'scanner', event:'scanner_missing_token', detail:'snyk'}
    );
  `);
  const html = run('workflowBody(project,workflow)');
  assert.match(html,/Enabled in Configuration · govulncheck, npm audit, composer audit, Snyk/);
  assert.match(html,/Starting scanner · npm audit/);
  assert.match(html,/Scanner completed · npm audit · 0 findings reported/);
  assert.match(html,/Scanner completed · govulncheck · 1 finding reported/);
  assert.match(html,/class="workflow-log-error"[^]*?Scanner failed · composer audit · &lt;failed&gt;/);
  assert.match(html,/Code scanners · Snyk skipped because its token is missing\./);
  run(`lang='ja'`);
  assert.match(run('workflowBody(project,workflow)'),/スキャナーが完了 · npm audit · 検出結果 0 件/);
});

test('code scan counts distinguish scanner reports, unique saves, and filtered results', () => {
  const run = app();
  workflowFixture(run);
  run(`
    workflow.mode = 'code';
    workflow.status = 'complete';
    workflow.steps = [
      {id:'scanner', kind:'scanner', status:'complete', progress:{phase:'scanning', item:'trivy', found:8}},
      {id:'save', kind:'save', status:'complete', progress:{found:4}},
    ];
    workflow.logs = ['govulncheck','trivy'].map(tool => ({at:workflow.started_at, step_id:'scanner', event:'scanner_completed', detail:tool, findings:4}));
    expandedRuns.add(workflow.id);
  `);
  const html = run('workflowBody(project,workflow)');
  assert.match(html,/Code scanners<\/strong><p>8 findings reported across scanners \(before deduplication\)/);
  assert.match(html,/Save assessment<\/strong><p>4 unique findings saved/);
  assert.match(html,/Scanner completed · Trivy · 4 findings reported/);
  assert.match(html,/Scanner completed · govulncheck · 4 findings reported/);
  assert.match(run('resultsSummary(4, 30719, 0, true)'),/Showing 4 matches \(30,719 total\)/);
  run(`workflow.steps[0].status='running';workflow.steps[0].progress.found=4`);
  assert.match(run('stepProgress(workflow.steps[0])'),/Trivy · 4 findings reported across scanners/);
  run(`lang='ja'`);
  assert.match(run('stepProgress(workflow.steps[1])'),/重複を統合した検出結果を 4 件保存しました/);
});

test('code scanner findings and workflow logs identify each repository location', () => {
  const run = app();
  workflowFixture(run);
  run(`
    const locations = ['local', 'remote'];
    workflow.logs = locations.map(scan_target => ({at:workflow.started_at, step_id:'scanner', event:'scanner_completed', detail:'trivy', scan_target, findings:1}));
    workflow.logs.push({at:workflow.started_at, step_id:'scanner', event:'scanner_target_failed', detail:'repository folder is unavailable', scan_target:'local'});
    const findings = locations.map((scan_target, i) => ({id:'CVE-both', asset_id:'code:'+scan_target+':demo', scan_target, component:'demo', version:String(i+1), title:'Advisory', match:'scanner', severity:'HIGH', sources:['Trivy']}));
    state = {projects:[{...project, assets:[], findings}]};
    expandedRuns.add(workflow.id);
  `);
  const logs = run('workflowBody(project,workflow)');
  assert.match(logs,/Local folder · Scanner completed · Trivy/);
  assert.match(logs,/Remote repository · Scanner completed · Trivy/);
  assert.match(logs,/class="workflow-log-error"[^]*?Local folder · Could not open scan target/);
  const table = run(`findingsTable('p')`);
  assert.equal(findingIDs(table).length,2);
  assert.match(table,/1 · Local folder/);
  assert.match(table,/2 · Remote repository/);
  run(`filter.stack=stackKey('p','code:remote:demo')`);
  assert.equal(findingIDs(run(`findingsTable('p')`)).length,1);
});

test('completed and failed steps advance work count without claiming a successful run',()=>{
  const run=app();workflowFixture(run);
  run(`workflow.steps[0].status='failed';workflow.steps[1].status='complete';workflow.steps[2].status='complete';workflow.status='partial'`);
  const html=run('workflowBody(project,workflow)');
  assert.match(html,/3 of 3 steps finished/);
  assert.match(html,/Partial/);
  assert.match(html,/<progress max="3" value="3"/);
  assert.equal(run(`workflowRun(project,{id:'legacy',status:'complete'})`),'');
});

test('a completed scoped workflow identifies where the earlier full-project sync was interrupted', () => {
  const run = app();
  workflowFixture(run);
  run(`
    workflow.status='complete';
    workflow.asset_id='go';
    workflow.asset_name='Go 1.26.3';
    workflow.severity='CRITICAL';
    workflow.steps.forEach(step => step.status='complete');
    const interruptedRun = {...workflow, id:'full-run', status:'interrupted', asset_id:'', asset_name:'', severity:'', steps:[
      {kind:'nvd', component:'demo 1', status:'complete'},
      {kind:'cve', status:'interrupted'},
      {kind:'save', status:'skipped'},
    ]};
    state = {projects:[{...project, assets:[], findings:[], schedule:'off', runs:[workflow, interruptedRun]}]};
    renderProject('p');
  `);
  const html = run(`$('#main').innerHTML`);
  assert.match(html, /<span class="pill interrupted full-sync-interruption">Full-project sync interrupted during CVE Program<\/span>/);
  assert.match(html, /class="sync-workflow complete"[^>]+data-sync-scope="scoped"/);
  assert.match(html, /Go 1\.26\.3 · Critical/);
  assert.match(html, /The latest full-project assessment is incomplete/);
});

test('interrupted workflow summaries report the recorded step or explicitly say it is unavailable', () => {
  const run = app();
  workflowFixture(run);
  run(`workflow.status='interrupted'; workflow.steps[0].status='interrupted'; workflow.steps[0].component='<demo>'`);
  let html = run('workflowRun(project,workflow,true)');
  assert.match(html, /class="sync-workflow interrupted"[^>]+data-sync-scope="full"/);
  assert.match(html, /role="status">Interrupted during NIST NVD · &lt;demo&gt;\.<\/div>/);
  run(`lang='ja'`);
  assert.match(run('workflowBody(project,workflow)'), /role="status">「NIST NVD · &lt;demo&gt;」で中断しました。/);
  run(`lang='en'; workflow.steps[0].status='complete'`);
  assert.match(run('workflowBody(project,workflow)'), /role="status">Workflow interrupted\. The interrupted step is unavailable\./);
});

test('workflow localizes interface and escapes external error details',()=>{
  const run=app();workflowFixture(run);
  run(`lang='ja';expandedRuns.add('run-1');workflow.logs.push({at:new Date().toISOString(),event:'failed',detail:'<script>unsafe</script>'})`);
  const html=run('workflowBody(project,workflow)');
  assert.match(html,/同期ワークフロー/);
  assert.match(html,/詳細を閉じる/);
  assert.match(html,/実行ログ/);
  assert.match(html,/&lt;script&gt;unsafe&lt;\/script&gt;/);
  assert.doesNotMatch(html,/<script>/);
});

test('polling progress updates panels without resetting active filters or rebuilding the page',()=>{
  const run=app();workflowFixture(run);
  run(`state={settings:{language:'en'},projects:[{...project,syncing:true,runs:[workflow]}]};filter.search='keep this';var pageRenders=0,panelUpdates=0;render=()=>pageRenders++;localize=()=>{};updateSyncPanels=()=>panelUpdates++;var next=JSON.parse(JSON.stringify(state));next.projects[0].runs[0].steps[0].progress.phase='page';next.projects[0].runs[0].logs.push({event:'page'});applyPollingState(next)`);
  assert.equal(run('pageRenders'),0);
  assert.equal(run('panelUpdates'),1);
  assert.equal(run('filter.search'),'keep this');
  run(`next=JSON.parse(JSON.stringify(state));next.projects[0].syncing=false;next.projects[0].runs[0].status='complete';applyPollingState(next)`);
  assert.equal(run('pageRenders'),1);
});

test('project pages, global views, and Activity mount workflow controls',()=>{
  const run=app();workflowFixture(run);
  run(`state={settings:{language:'en'},projects:[{...project,assets:[],findings:[],runs:[workflow],syncing:true,schedule:'off',revision:1,assessed_revision:0}]};render()`);
  assert.match(run(`document.querySelector('#main').innerHTML`),/data-sync-run="run-1"/);
  run(`location.hash='#vulnerabilities';render()`);
  assert.match(run(`document.querySelector('.page-heading').insertedHTML`),/id="active-syncs"/);
  assert.match(run(`document.querySelector('.page-heading').insertedHTML`),/data-sync-run="run-1"/);
  run(`state.projects[0].syncing=false;workflow.status='complete';location.hash='#activity';render()`);
  assert.match(run(`document.querySelector('#main').innerHTML`),/data-sync-run="run-1"/);
});

test('project workflow can be closed only after the run finishes',()=>{
  const run=app();workflowFixture(run);
  run(`state={projects:[{...project,runs:[workflow]}]}`);
  assert.doesNotMatch(run('workflowRun(project,workflow,true)'),/data-dismiss-workflow/);
  assert.equal(run(`dismissWorkflow('p','run-1')`),false);
  for(const status of ['complete','partial','failed','interrupted']) {
    run(`workflow.status=${JSON.stringify(status)}`);
    assert.match(run('workflowRun(project,workflow,true)'),/data-dismiss-workflow="run-1"/);
  }
  assert.doesNotMatch(run('workflowRun(project,workflow)'),/data-dismiss-workflow/);
  run(`lang='ja'`);
  assert.match(run('workflowRun(project,workflow,true)'),/aria-label="同期ワークフローを閉じる"/);
});

test('closing a workflow removes only its project panel and preserves filters and history',()=>{
  const run=app();workflowFixture(run);
  run(`workflow.status='complete';state={projects:[{...project,runs:[workflow]}]};filter.search='keep this';var removed=0;document.querySelectorAll=()=>[{dataset:{syncProjectId:'p',syncRun:'run-1',workflowDismissible:'true'},remove(){removed++;}},{dataset:{syncProjectId:'p',syncRun:'run-1',workflowDismissible:'false'},remove(){throw new Error('History must remain');}}]`);
  assert.equal(run(`dismissWorkflow('p','run-1')`),true);
  assert.equal(run('removed'),1);
  assert.equal(run('filter.search'),'keep this');
  assert.equal(run('state.projects[0].runs.length'),1);
  assert.equal(run('workflowRun(project,workflow,true)'),'');
  assert.match(run('workflowRun(project,workflow)'),/data-sync-run="run-1"/);
});

test('dismissed project panel stays closed on redraw and a new run displays normally',()=>{
  const run=app();workflowFixture(run);
  run(`workflow.status='complete';state={settings:{language:'en'},projects:[{...project,assets:[],findings:[],runs:[workflow],syncing:false,schedule:'off',revision:1,assessed_revision:0}]};dismissWorkflow('p','run-1');renderProject('p')`);
  assert.doesNotMatch(run(`document.querySelector('#main').innerHTML`),/data-sync-run="run-1"/);
  run(`projectTab='techStack';renderProject('p');projectTab='vulnerabilities';renderProject('p')`);
  assert.doesNotMatch(run(`document.querySelector('#main').innerHTML`),/data-sync-run="run-1"/);
  run(`var fresh={...workflow,id:'run-2',status:'running'};state.projects[0].runs.unshift(fresh);state.projects[0].syncing=true;renderProject('p')`);
  assert.match(run(`document.querySelector('#main').innerHTML`),/data-sync-run="run-2"/);
  assert.doesNotMatch(run(`document.querySelector('#main').innerHTML`),/data-dismiss-workflow/);
});

test('Configuration shows runtime database and key paths beneath the storage note',()=>{
  const run=app();
  run(`state={settings:{language:'en',sources:{},scanners:{}},token_status:{github:true,snyk:true},saved_token_status:{github:true},storage_paths:{database:'/custom data/vulman.db',key:'/custom data/vulman.key'}};renderSettings()`);
  const html=run(`document.querySelector('#main').innerHTML`);
  assert.match(html,/<code>\/custom data\/vulman.db<\/code>/);
  assert.match(html,/<code>\/custom data\/vulman.key<\/code>/);
  assert.match(html,/GitHub personal access token[^]*?type="password" name="token_github"/);
  assert.match(html, /<input[^>]+name="token_github"[^>]*placeholder="••••••"/);
  assert.match(html, /<input[^>]+name="token_snyk"[^>]*placeholder=""/);
  assert.equal([...html.matchAll(/data-credential-toggle=/g)].length, 5);
  assert.ok(html.indexOf('Local storage uses AES-GCM')<html.indexOf('class="storage-paths"'));
  run(`lang='ja'`);
  assert.match(run('storagePathsHTML()'),/暗号化キーファイル/);
  const windowsPath=String.raw`C:\Users\Example\Vulman\vulman.db`;
  run(`state.storage_paths.database=${JSON.stringify(windowsPath)}`);
  assert.ok(run('storagePathsHTML()').includes(windowsPath));
  run(`state.storage_paths.key='/custom/<data>&/vulman.key'`);
  assert.match(run('storagePathsHTML()'),/\/custom\/&lt;data&gt;&amp;\/vulman.key/);
});

test('sync modes are explicit and keep the selected mode after redraw',async()=>{
  const run=app();run(`var p={id:'p',assets:[]};syncModeSelection.p='local'`);
  const html=run('syncControls(p)');
  assert.match(html,/value="local" selected>Reassess from cache/);
  assert.match(html,/Force refresh/);
  run(`var calls=[];invoke=async(_method,_id,body)=>calls.push(body);refresh=async()=>{};toast=()=>{}`);
  await run(`syncProject('p','','local')`);await run(`syncProject('p','a','refresh')`);
  assert.deepEqual(JSON.parse(run('JSON.stringify(calls)')),[{mode:'local'},{asset_id:'a',mode:'refresh'}]);
});

test('cache settings expose configurable freshness and runtime cache usage',()=>{
  const run=app();run(`state={settings:{cache_hours:12},cache_stats:{entries:5,bytes:1048576}}`);
  let html=run('cacheSettingsHTML()');
  assert.match(html,/name="cache_hours"[^>]*value="12"/);
  assert.match(html,/Cached queries and records: <strong>5/);
  assert.match(html,/1.00 MiB/);
  run(`lang='ja'`);assert.match(run('cacheSettingsHTML()'),/共有ローカルキャッシュ/);
});

test('workflow distinguishes assessment time from cached source freshness',()=>{
  const run=app();workflowFixture(run);
  run(`workflow.mode='local';workflow.data_checked_at='2026-01-01T01:00:00Z';workflow.steps[0].progress={phase:'stale_cache',cache_status:'stale',checked_at:workflow.data_checked_at}`);
  const html=run('workflowBody(project,workflow)');
  assert.match(html,/Reassess from cache/);
  assert.match(html,/Source data checked/);
  assert.match(html,/freshness could not be verified/);
  assert.match(html,/Stale cached data/);
});

test('cache metadata polling preserves the active page and filters',()=>{
  const run=app();workflowFixture(run);
  run(`state={settings:{language:'en'},cache_stats:{entries:0,bytes:0},projects:[{...project,syncing:true,runs:[workflow]}]};var pageRenders=0,panelUpdates=0;render=()=>pageRenders++;updateSyncPanels=()=>panelUpdates++;localize=()=>{};var next=JSON.parse(JSON.stringify(state));next.cache_stats.entries=1;next.projects[0].runs[0].data_checked_at='2026-01-01T00:00:00Z';applyPollingState(next)`);
  assert.equal(run('pageRenders'),0);assert.equal(run('panelUpdates'),1);
});

test('cache capacity controls default to larger limits and show configured capacity',()=>{
  const run=app();run(`state={settings:{cache_hours:6},cache_stats:{}}`);
  let html=run('cacheSettingsHTML()');
  assert.match(html,/name="cache_max_entries"[^>]*value="10000"/);
  assert.match(html,/name="cache_max_mib"[^>]*value="512"/);
  assert.match(html,/10,000 entries \/ 512 MiB/);
  assert.match(html,/Maximum 8 MiB per entry/);
  run(`state.settings.cache_max_entries=25000;state.settings.cache_max_mib=1024`);
  html=run('cacheSettingsHTML()');assert.match(html,/25,000 entries \/ 1,024 MiB/);
  run(`lang='ja'`);assert.match(run('cacheSettingsHTML()'),/キャッシュ件数の上限/);
});

test('cache metrics show hit rate and evictions without an invalid empty ratio',()=>{
  const run=app();run(`state={settings:{},cache_stats:{hits:9,misses:3,evictions:7}}`);
  let html=run('cacheSettingsHTML()');
  assert.match(html,/Fresh cache hits<\/span><strong>9/);
  assert.match(html,/Cache misses<\/span><strong>3/);
  assert.match(html,/Cache hit rate<\/span><strong>75.0%/);
  assert.match(html,/Capacity evictions<\/span><strong>7/);
  run(`state.cache_stats={}`);html=run('cacheSettingsHTML()');assert.match(html,/Cache hit rate<\/span><strong>—/);assert.doesNotMatch(html,/NaN|Infinity/);
});

test('configuration saves cache settings and the GitHub credential',async()=>{
  const run=app();
  run(`state={settings:{},cache_stats:{}};var sent;invoke=async(_method,body)=>{sent=body};refresh=async()=>{};toast=()=>{};var elements={};for(const key of ['language','nvd_url','cve_url','osv_url','ai_provider','openai_model','claude_model'])elements[key]={value:'value'};for(const key of ['nvd','cve','osv'])elements['source_'+key]={checked:true};for(const key of Object.keys(scannerLabels))elements['scanner_'+key]={checked:key==='pip-audit'};for(const key of ['nvd','openai','claude','snyk'])elements['token_'+key]={value:''};elements.token_github={value:' fixture-token '};elements.cache_hours={value:'12'};elements.cache_max_entries={value:'25000'};elements.cache_max_mib={value:'1024'}`);
  run(`var submitSettings = () => saveSettings({preventDefault(){},target:{elements,querySelector(){return {disabled:false}},querySelectorAll(){return []}}});`);
  await run('submitSettings()');
  assert.equal(run('sent.cache_hours'),12);assert.equal(run('sent.cache_max_entries'),25000);assert.equal(run('sent.cache_max_mib'),1024);
  assert.equal(run('sent.tokens.github'),'fixture-token');
  assert.equal(run("sent.scanners['pip-audit']"),true);
  assert.equal(run('elements.token_github.value'), '');
  run(`location.hash = githubTokenSettingsHash; projectTokenSetup = {returnHash:'#project/p/edit'}; elements.token_github.value = 'fixture-token';`);
  await run('submitSettings()');
  assert.equal(run('location.hash'), '#project/p/edit');
});

test('the credential eye reveals drafts and displays saved previews inside the field', async () => {
  const calls = [];
  const run = app((...args) => {
    calls.push(args);
    return Promise.resolve('0123456789xxxxWXYZ');
  });
  run(`
    var classes = () => {
      const values = new Set();
      return {
        add: value => values.add(value), remove: value => values.delete(value), contains: value => values.has(value),
        toggle: (value, enable) => enable ? values.add(value) : values.delete(value),
      };
    };
    var form = {querySelector: () => ({disabled:false})};
    var input = {type:'password', value:'draft key', placeholder:'••••••', dataset:{credentialSaved:'true'}, form, matches: () => true, focus(){},
      closest: selector => selector === '.credential-field' ? field : input};
    var preview = {textContent:'', classList:classes()};
    var attrs = {'aria-pressed':'false'};
    var eye = {
      dataset:{action:'toggle-credential', credentialToggle:'github'}, isConnected:true,
      getAttribute: name => attrs[name], setAttribute: (name,value) => {attrs[name] = value;},
      closest: selector => ({'[data-action]':eye, '.credential-field':field, form})[selector],
    };
    var remove = {dataset:{clearToken:'github'}, closest: selector => ({'[data-clear-token]':remove, '.credential-field':field})[selector]};
    var field = {classList:classes(), querySelector: selector => ({
      '[data-credential-input]':input, '[data-credential-toggle]':eye, '.credential-preview':preview, '[data-clear-token]':remove,
      '.credential-preview-inline':preview.classList.contains('credential-preview-inline') ? preview : null,
    })[selector]};
    var clickEye = () => document.listeners.click({target:eye});
    var press = (key, modifiers = {}) => {
      let prevented = false;
      document.listeners.keydown({target:input,key,...modifiers,preventDefault(){prevented = true;}});
      return prevented;
    };
  `);
  await run('clickEye()');
  assert.equal(run('input.type'), 'text');
  assert.equal(run('input.value'), 'draft key');
  await run('clickEye()');
  assert.equal(run('input.type'), 'password');
  assert.deepEqual(calls, []);
  run(`input.value = ''; document.listeners.input({target:input});`);
  assert.equal(run('input.type'), 'password');
  assert.equal(run('input.placeholder'), '');
  await run('clickEye()');
  assert.deepEqual(calls, [['main.Desktop.SavedCredentialPreview', 'github']]);
  assert.equal(run('preview.textContent'), '0123456789xxxxWXYZ');
  assert.equal(run('input.placeholder'), '');
  assert.equal(run('input.value'), '');
  assert.equal(run(`press('a', {metaKey:true})`), true);
  assert.equal(run(`field.classList.contains('credential-preview-selected')`), true);
  assert.equal(run(`press('Backspace')`), true);
  assert.equal(run(`clearing.has('github')`), true);
  assert.equal(run('preview.textContent'), '');
  run(`input.value = 'replacement'; document.listeners.input({target:input});`);
  assert.equal(run(`clearing.has('github')`), false);
  run(`input.value = ''; document.listeners.input({target:input});`);
  await run('clickEye()');
  await run('clickEye()');
  assert.equal(run('preview.textContent'), '');
  assert.equal(run('input.placeholder'), '••••••');
  assert.equal(run(`press('a', {ctrlKey:true})`), true);
  assert.equal(run(`press('Delete')`), true);
  assert.equal(run(`clearing.has('github')`), true);
  assert.equal(run('input.placeholder'), '');
  run(`input.value = 'replacement'; document.listeners.input({target:input}); input.value = ''; document.listeners.input({target:input});`);

  run(`var finishPreview; invoke = () => new Promise(resolve => {finishPreview = resolve}); var pending = clickEye();`);
  run(`input.value = 'replacement'; document.listeners.input({target:input}); finishPreview('0123456789xxxxWXYZ');`);
  await run('pending');
  assert.equal(run('input.type'), 'password');
  assert.equal(run('input.placeholder'), '');
  assert.equal(run('preview.textContent'), '');
  assert.equal(run('input.value'), 'replacement');

  await run(`document.listeners.click({target:remove});`);
  assert.equal(run('input.value'), '');
  assert.equal(run('input.placeholder'), '');
  assert.equal(run('preview.textContent'), '');
  assert.equal(run(`clearing.has('github')`), true);
});

test('Configuration refreshes cache metrics without replacing unsaved settings',()=>{
  const run=app();run(`location.hash='#settings';state={settings:{cache_max_entries:25000,cache_max_mib:1024},projects:[],cache_stats:{}};var pageRenders=0;render=()=>pageRenders++;applyPollingState({settings:{cache_max_entries:10000,cache_max_mib:512},projects:[],cache_stats:{hits:9,misses:3,evictions:7,entries:5,bytes:1048576}})`);
  assert.equal(run('pageRenders'),0);assert.equal(run('state.settings.cache_max_entries'),25000);
  assert.match(run(`document.querySelector('#cache-metrics').innerHTML`),/75.0%/);
  assert.match(run(`document.querySelector('#cache-metrics').innerHTML`),/Capacity evictions<\/span><strong>7/);
  assert.match(run(`document.querySelector('#cache-usage').innerHTML`),/1.00 MiB/);
});

test('project sync controls default to all severities and preserve the selected level',()=>{
  const run=app();run(`var p={id:'p',assets:[]}`);
  let select=run('syncControls(p)').match(/<select id="sync-severity"[\s\S]*?<\/select>/)[0];
  assert.match(select,/<option value="">All severities<\/option>/);assert.doesNotMatch(select,/<option[^>]* selected/);
  run(`syncSeveritySelection.p='CRITICAL'`);select=run('syncControls(p)').match(/<select id="sync-severity"[\s\S]*?<\/select>/)[0];
  assert.match(select,/value="CRITICAL" selected>Critical/);
  assert.match(select,/value="UNKNOWN"[^>]*>Unrated/);
  run(`lang='ja'`);assert.match(run('syncControls(p)'),/深刻度別の同期/);
});

test('severity sync requests combine with a tech stack and refresh mode',async()=>{
  const run=app();run(`var calls=[];invoke=async(_method,_id,body)=>calls.push(body);refresh=async()=>{};toast=()=>{}`);
  await run(`syncProject('p','a','refresh','CRITICAL')`);
  await run(`syncProject('p','','local','UNKNOWN')`);
  assert.deepEqual(JSON.parse(run('JSON.stringify(calls)')),[{asset_id:'a',mode:'refresh',severity:'CRITICAL'},{mode:'local',severity:'UNKNOWN'}]);
});

test('global sync controls offer severity selection independently of display filters',()=>{
  const run=app();run(`syncAllSeverity='HIGH';filter.severity='LOW'`);
  const html=run('syncAllControls(true)');
  assert.match(html,/id="sync-all-severity"/);assert.match(html,/value="HIGH" selected>High/);assert.match(html,/data-action="sync-all"/);
  assert.equal(run('filter.severity'),'LOW');
});

test('severity-scoped workflows identify their scope without claiming full-project completion',()=>{
  const run=app();workflowFixture(run);run(`workflow.severity='CRITICAL'`);
  assert.match(run('workflowBody(project,workflow)'),/Everything · Critical · Normal sync/);
  const html=run(`projectStatus({revision:1,assessed_revision:0,last_sync:'0001-01-01T00:00:00Z',runs:[{severity:'CRITICAL',status:'complete'}]})`);
  assert.match(html,/Full-project assessment needed/);
  const partial=run(`projectStatus({revision:1,assessed_revision:1,last_sync:'2026-01-01',runs:[{severity:'HIGH',status:'complete'},{status:'partial'}]})`);
  assert.match(partial,/Partial/);
});

test('only interrupted, partial, and failed activity entries offer deletion in English and Japanese',()=>{
  const run=app();workflowFixture(run);
  run(`workflow.project_id='p';workflow.project_name='Project One'`);
  for(const status of ['interrupted','partial','failed']){
    run(`workflow.status=${JSON.stringify(status)}`);
    assert.match(run('activityList([workflow])'),/data-action="delete-activity" data-id="p" data-run="run-1">Delete activity/);
  }
  for(const status of ['running','complete','pending','']){
    run(`workflow.status=${JSON.stringify(status)}`);
    assert.doesNotMatch(run('activityList([workflow])'),/data-action="delete-activity"/);
  }
  run(`lang='ja';workflow.status='partial'`);
  assert.match(run('activityList([workflow])'),/>履歴を削除<\/button>/);
});

test('deleting activity requires confirmation and leaves running and completed entries protected',async()=>{
  const run=app();workflowFixture(run);
  run(`state={projects:[{...project,runs:[workflow]}]};var calls=0,prompts=0;confirmAction=()=>{prompts++;return true};invoke=async()=>{calls++}`);
  assert.equal(await run(`deleteActivity('p','run-1')`),false);
  run(`workflow.status='complete'`);
  assert.equal(await run(`deleteActivity('p','run-1')`),false);
  assert.equal(await run(`deleteActivity('wrong-project','run-1')`),false);
  assert.equal(run('prompts'),0);
  run(`workflow.status='interrupted';confirmAction=()=>{prompts++;return false}`);
  assert.equal(await run(`deleteActivity('p','run-1')`),false);
  assert.equal(run('prompts'),1);assert.equal(run('calls'),0);
  assert.equal(run('state.projects[0].runs.length'),1);
});

test('deleting activity refreshes history while keeping filters and handles a rejected request',async()=>{
  const run=app();workflowFixture(run);
  run(`workflow.status='partial';state={projects:[{...project,runs:[workflow]}]};filter.search='keep';expandedRuns.add('run-1');dismissedRuns.add('run-1');var calls=[],refreshes=0,notice='';confirmAction=()=>true;invoke=async()=>{throw new Error('Cannot delete')};refresh=async()=>{refreshes++};toast=message=>notice=message`);
  await assert.rejects(run(`deleteActivity('p','run-1')`),/Cannot delete/);
  assert.equal(run('refreshes'),0);assert.equal(run(`expandedRuns.has('run-1')`),true);
  assert.equal(run(`dismissedRuns.has('run-1')`),true);
  run(`invoke=async(...args)=>calls.push(args)`);
  assert.equal(await run(`deleteActivity('p','run-1')`),true);
  assert.deepEqual(JSON.parse(run('JSON.stringify(calls)')),[['DeleteRun','p','run-1']]);
  assert.equal(run('refreshes'),1);assert.equal(run('notice'),'Activity deleted.');
  assert.equal(run('filter.search'),'keep');assert.equal(run(`expandedRuns.has('run-1')`),false);
  assert.equal(run(`dismissedRuns.has('run-1')`),false);
});

test('Tech stack tab offers Add component for empty and populated projects and disables it during sync',()=>{
  const run=app();inventory(run);run(`projectTab='techStack';renderProject('p')`);
  assert.match(run(`document.querySelector('#project-tab-content').innerHTML`),/data-action="add-component" data-id="p" >\+ Add component/);
  run(`state.projects[0].assets=[];renderProject('p')`);
  const empty=run(`document.querySelector('#project-tab-content').innerHTML`);
  assert.match(empty,/data-action="add-component"/);assert.match(empty,/No components registered/);
  run(`state.projects[0].syncing=true;renderProject('p')`);
  assert.match(run(`document.querySelector('#project-tab-content').innerHTML`),/data-action="add-component" data-id="p" disabled/);
  run(`lang='ja';state.projects[0].syncing=false;renderProject('p')`);
  assert.match(run(`document.querySelector('#project-tab-content').innerHTML`),/\+ コンポーネントを追加/);
});

function componentDialog(run){
  inventory(run);
  run(`var focused=0,opened=0,closed=0;document.createElement=()=>({dataset:{},innerHTML:'',querySelector:()=>({focus(){focused++}})});document.querySelector('#component-form').reset=()=>{};document.querySelector('#component-fields').append=el=>{document.querySelector('#component-fields').field=el};document.querySelector('#component-fields').querySelectorAll=()=>[];document.querySelector('#component-dialog').showModal=()=>opened++;document.querySelector('#component-dialog').close=()=>closed++;localize=()=>{}`);
}

test('Add component opens a blank focused form without changing project inventory',()=>{
  const run=app();componentDialog(run);
  assert.equal(run(`openComponent('missing')`),false);
  run(`state.projects[0].syncing=true`);
  assert.equal(run(`openComponent('p')`),false);
  run(`state.projects[0].syncing=false`);
  assert.equal(run(`openComponent('p')`),true);
  const html=run(`document.querySelector('#component-fields').field.innerHTML`);
  assert.match(html,/data-field="name" value="" required/);
  assert.match(html,/data-field="version" value="" required/);
  assert.match(html,/data-field="ecosystem"/);assert.match(html,/data-field="cpe"/);
  assert.doesNotMatch(html,/asset-remove/);
  assert.equal(run('focused'),1);assert.equal(run('opened'),1);
  assert.equal(run(`state.projects[0].assets.length`),2);
  run(`componentDraft.assets[0].version='changed draft'`);
  assert.equal(run(`state.projects[0].assets[0].version`),'1');
});

test('saving a component appends to the captured inventory and keeps project metadata and revision',async()=>{
  const run=app();componentDialog(run);
  run(`Object.assign(state.projects[0],{description:'Description',repository:'https://example.com/repo',repository_urls:['https://example.com/repo','https://example.com/second'],local_path:'/project',schedule:'weekly',scan_code:true,revision:7});openComponent('p');var calls=[],rendered=0;document.querySelector('#component-fields').querySelectorAll=()=>[{dataset:{field:'kind'},value:'library'},{dataset:{field:'name'},value:' new/package '},{dataset:{field:'version'},value:' 2 '},{dataset:{field:'ecosystem'},value:'Go'},{dataset:{field:'cpe'},value:''}];invoke=async(...args)=>{calls.push(args);return {id:'p'}};refresh=async()=>{};render=()=>rendered++;toast=()=>{};state.projects[0].revision=8;state.projects[0].assets=[]`);
  await run(`saveComponent({preventDefault(){}})`);
  const [method, project, body]=JSON.parse(run('JSON.stringify(calls[0])'));
  assert.equal(method,'UpdateProject');assert.equal(project,'p');
  assert.equal(body.name,'Project One');assert.equal(body.description,'Description');
  assert.equal(body.repository,'https://example.com/repo');assert.equal(body.local_path,'/project');
  assert.deepEqual(body.repository_urls,['https://example.com/repo','https://example.com/second']);
  assert.equal(body.schedule,'weekly');assert.equal(body.scan_code,true);assert.equal(body.revision,7);
  assert.equal(body.assets.length,3);assert.equal(body.assets[0].id,'shared');
  assert.deepEqual(body.assets[2],{kind:'library',name:'new/package',version:'2',ecosystem:'Go',cpe:''});
  assert.equal(run('closed'),1);assert.equal(run('rendered'),1);assert.equal(run('componentDraft'),null);
  assert.equal(run('projectTab'),'techStack');assert.equal(run(`document.querySelector('#save-component').disabled`),false);
});

test('a rejected component save keeps the form and entered values available for correction',async()=>{
  const run=app();componentDialog(run);
  run(`openComponent('p');invoke=async()=>{throw new Error('Project changed; reload before saving')};refresh=async()=>{throw new Error('Must not refresh')}`);
  await run(`saveComponent({preventDefault(){}})`);
  assert.equal(run('closed'),0);assert.notEqual(run('componentDraft'),null);
  assert.equal(run(`document.querySelector('#component-error').textContent`),'Project changed; reload before saving');
  assert.equal(run(`document.querySelector('#save-component').disabled`),false);
  assert.equal(run('state.projects[0].assets.length'),2);
});

test('editing a project reads only its own component fields when the separate component dialog exists',async()=>{
  const run=app();inventory(run);
  run(`
    location.hash = '#project/p/edit';
    state.projects[0].revision = 4;
    const calls = [];
    const controls = {'button[type="submit"]':{}, '[data-project-error]':{}};
    const form = {
      dataset:{projectId:'p', revision:'3'}, isConnected:true, closest:() => null,
      elements:{name:{value:'Project One'}, description:{value:''}, local_path:{value:'/project'}, schedule:{value:'off'}, scan_code:{checked:true}},
      querySelector:selector => controls[selector],
      querySelectorAll:selector => selector === '[data-repository-url]' ? [{value:'https://example.test/first'}, {value:''}, {value:' https://example.test/second '}] : [{dataset:{id:'shared'}, querySelectorAll:() => [
        {dataset:{field:'kind'}, value:'library'}, {dataset:{field:'name'}, value:'demo'}, {dataset:{field:'version'}, value:'1'}
      ]}],
    };
    document.querySelectorAll = () => {throw new Error('Must scope component fields to the project form');};
    invoke = async (...args) => {calls.push(args); return {id:'p'};};
    refresh = async () => {};
    toast = () => {};
  `);
  await run(`saveProject({preventDefault(){},target:form})`);
  const [method, id, body] = JSON.parse(run('JSON.stringify(calls[0])'));
  assert.equal(method,'UpdateProject');
  assert.equal(id,'p');
  assert.deepEqual(body.assets,[{id:'shared',kind:'library',name:'demo',version:'1'}]);
  assert.equal(body.revision,3);
  assert.equal(body.local_path,'/project');
  assert.deepEqual(body.repository_urls,['https://example.test/first','https://example.test/second']);
  assert.equal(body.scan_code,true);
  assert.equal(run('location.hash'),'project/p');
});

test('repository URL rows can be added and removed, and legacy projects still link to their repository', async () => {
  const run = app();
  run(`
    const rows = [];
    const list = {append: row => rows.push(row)};
    let focused = '';
    document.createElement = () => {
      const row = {querySelector: () => ({focus: () => {focused = 'input';}}), remove: () => rows.splice(rows.indexOf(row), 1)};
      return row;
    };
    const form = {querySelector: selector => selector === '[data-project-repositories]' ? list : add};
    const control = (action, row) => {
      const target = {dataset:{action}, closest:selector => ({'[data-action]':target, form, '.project-repository':row})[selector]};
      return target;
    };
    const add = control('add-repository');
    add.focus = () => {focused = 'add';};
    list.append(repositoryField('https://example.test/legacy.git'));
  `);
  await run(`document.listeners.click({target:add})`);
  assert.equal(run('rows.length'),2);
  assert.equal(run('focused'),'input');
  await run(`document.listeners.click({target:control('remove-repository', rows[1])})`);
  assert.equal(run('rows.length'),1);
  assert.match(run('rows[0].innerHTML'),/https:\/\/example.test\/legacy.git/);
  assert.match(run(`projectRepositoryLinks({repository:'https://example.test/legacy.git'})`),/Open repository ↗/);
  assert.match(run(`projectRepositoryLinks({repository_urls:['https://example.test/first','https://example.test/second']})`),/Open repository 2 ↗/);
});

test('repository and component removal warnings appear only when editing a saved project', () => {
  const html = fs.readFileSync(path.join(__dirname,'../cmd/vulman/ui/index.html'),'utf8');
  const warnings = [...html.matchAll(/data-project-removal-warning data-t="([^"]+)" hidden>/g)].map(match => match[1]);
  assert.deepEqual(warnings, ['repositoryRemovalWarning', 'componentRemovalWarning']);

  const run = app();
  run(`
    const removalWarnings = ${JSON.stringify(warnings.map(key => ({hidden:true,dataset:{t:key}})))};
    var mountWarnings = project => {
      removalWarnings.forEach(warning => {warning.hidden=true;});
      const fieldList = {append(){}};
      const form = {
        dataset:{}, elements:Object.fromEntries([...projectTextFields,'scan_code'].map(key => [key,{}])),
        querySelector:() => fieldList, querySelectorAll:() => removalWarnings, addEventListener(){},
      };
      $('#project-form-template').content = {firstElementChild:{cloneNode:() => form}};
      repositoryField = componentFields = () => ({});
      localize = scope => scope.querySelectorAll().forEach(warning => {warning.textContent=t(warning.dataset.t);});
      mountProjectForm({replaceChildren(){}}, project);
      return JSON.stringify(removalWarnings.map(({hidden,textContent}) => ({hidden,textContent})));
    };
  `);
  const newProject = JSON.parse(run('mountWarnings()'));
  assert.ok(newProject.every(warning => warning.hidden));
  const edit = JSON.parse(run(`mountWarnings({id:'p',revision:1})`));
  assert.ok(edit.every(warning => !warning.hidden));
  assert.deepEqual(edit.map(warning => warning.textContent), warnings.map(key => bundledLocalizations.en.messages[key]));
  run(`lang='ja'`);
  const japanese = JSON.parse(run(`mountWarnings({id:'p',revision:1})`));
  assert.ok(japanese.every(warning => /削除/.test(warning.textContent)));
});

test('GitHub credential setup focuses the token and restores the project draft', async t => {
  for (const editing of [true, false]) {
    await t.test(editing ? 'edit project page' : 'new project page', async () => {
      const run = app();
      run(`
        const editing = ${editing};
        const origin = editing ? '#project/p/edit' : '#projects/new';
        location.hash = origin;
        state = {projects:[{id:'p', name:'Saved name', revision:4, assets:[]}], settings:{sources:{}, scanners:{}}, token_status:{}};
        const events = [], mounts = [];
        const token = $('#settings-form input[name="token_github"]');
        token.scrollIntoView = () => events.push('scroll to token');
        token.focus = () => events.push('focus token');
        const container = $('#project-editor');
        container.querySelector = () => ({focus: () => events.push('focus setup button')});
        mountProjectForm = (target, draft) => mounts.push(draft);
        const form = {
          dataset: editing ? {projectId:'p',revision:'3'} : {},
          elements: {name:{value:'Draft name'},description:{value:'Draft description'},local_path:{value:'/local'},schedule:{value:'weekly'},scan_code:{checked:true}},
          querySelector: () => ({disabled:false}),
          querySelectorAll: selector => selector === '[data-repository-url]' ? [{value:'https://github.com/owner/private'}, {value:''}] : [],
        };
        const control = action => ({dataset:{action}, closest(selector) {return selector === '[data-action]' ? this : selector === 'form' ? form : null;}});
      `);
      await run(`document.listeners.click({target:control('configure-github-token')})`);
      assert.equal(run('location.hash'), '#settings/github');
      run('window.listeners.hashchange()');
      assert.match(run(`$('#main').innerHTML`), /name="token_github"[^]*?Back to project form/);
      await run(`document.listeners.click({target:control('return-to-project-form')})`);
      assert.equal(run('location.hash'), run('origin'));
      run('window.listeners.hashchange()');
      assert.deepEqual(JSON.parse(run('JSON.stringify(mounts[0])')), {
        scan_code:true, name:'Draft name', description:'Draft description', local_path:'/local', schedule:'weekly',
        repository_urls:['https://github.com/owner/private', ''], assets:[], ...(editing ? {id:'p', revision:'3'} : {}),
      });
      assert.deepEqual(JSON.parse(run('JSON.stringify(events)')), ['scroll to token', 'focus token', 'focus setup button']);
    });
  }
});

test('Add project opens the shared scrollable editor and supports saving and cancelling', async () => {
  const run = app();
  inventory(run);
  run(`
    const add = {dataset:{action:'new-project'}, closest:selector => selector === '[data-action]' ? add : null};
    const inputs = {name:{value:'  New project  '}, description:{value:''}, local_path:{value:''}, schedule:{value:'weekly'}, scan_code:{checked:true}};
    const submit = {}, formError = {};
    const form = {
      dataset:{language:'en'}, elements:inputs, isConnected:true,
      querySelector:selector => ({'button[type="submit"]':submit, '[data-project-error]':formError})[selector],
      querySelectorAll:selector => selector === '[data-repository-url]' ? [{value:' https://github.com/owner/repo '}, {value:''}] : [],
    };
    const mounts = [], requests = [];
    mountProjectForm = (container, project) => mounts.push([container, project]);
    window.scrollTo = (x,y) => {window.scrolled = [x,y];};
    invoke = async (...args) => {requests.push(args); return {id:'created'};};
    refresh = async () => {};
    toast = () => {};
    location.hash = '#overview';
  `);
  await run('document.listeners.click({target:add})');
  assert.equal(run('location.hash'), '#projects/new');
  run('window.listeners.hashchange()');
  assert.match(run(`$('#main').innerHTML`), /<h1>New project<\/h1>[^]*?id="project-editor" class="panel project-editor"/);
  assert.doesNotMatch(run(`$('#main').innerHTML`), /<dialog|data-action="delete-project"/);
  assert.match(run(`$('#nav').innerHTML`), /class="nav-link active" href="#projects"/);
  assert.equal(run('JSON.stringify(window.scrolled)'), '[0,0]');
  run(`
    $('#project-editor form').dataset = form.dataset;
    applyPollingState({...state, projects:[{...state.projects[0],revision:8}]});
    render();
  `);
  assert.equal(run('mounts.length'), 1);
  assert.equal(run('state.projects[0].revision'), 8);
  run('cancelProject(form)');
  assert.equal(run('location.hash'), '#overview');

  run(`$('#project-editor form').dataset = undefined; location.hash = '#projects';`);
  await run('document.listeners.click({target:add})');
  run('window.listeners.hashchange()');
  await run('saveProject({preventDefault(){},target:form})');
  assert.deepEqual(JSON.parse(run('JSON.stringify(requests)')), [
    ['CreateProject', {name:'New project', description:'', local_path:'', schedule:'weekly', scan_code:true,
      repository_urls:['https://github.com/owner/repo'], assets:[]}],
  ]);
  assert.equal(run('location.hash'), 'project/created');
});

test('Projects list opens the editor directly and polling leaves its draft mounted', async () => {
  const run = app();
  inventory(run);
  run(`
    const edit = {dataset:{action:'edit-project', id:'p'}, closest:selector => selector === '[data-action]' ? edit : null};
    const mounts = [];
    mountProjectForm = (container, project) => mounts.push([container, project]);
    window.scrollTo = (x,y) => {window.scrolled = [x,y];};
    state.projects[1].syncing = true;
    location.hash = '#projects';
    render();
  `);
  const list = run(`$('#main').innerHTML`);
  assert.match(list, /href="#project\/p"[^]*?<\/a><button[^>]+data-action="edit-project" data-id="p"[^>]*>Edit project/);
  assert.match(list, /data-action="edit-project" data-id="q"[^>]+disabled>Edit project/);
  assert.doesNotMatch(run('projectList(state.projects)'), /data-action="edit-project"/);
  await run('document.listeners.click({target:edit})');
  assert.equal(run('location.hash'), 'project/p/edit');
  run(`location.hash = '#project/p/edit'; window.listeners.hashchange();`);
  assert.match(run(`$('#main').innerHTML`), /<h1>Edit project<\/h1><\/div>/);
  assert.doesNotMatch(run(`$('#main').innerHTML`), /<dialog/);
  assert.equal(run(`mounts[0][0] === $('#project-editor')`), true);
  assert.equal(run(`mounts[0][1].id`), 'p');
  assert.equal(run('JSON.stringify(window.scrolled)'), '[0,0]');
  run(`applyPollingState({...state, projects:[{...state.projects[0], revision:8}]});`);
  assert.equal(run('state.projects[0].revision'), 8);
  assert.equal(run('mounts.length'), 1);
});

test('Projects list shows configured URL counts and each project’s Critical findings', () => {
  const run = app();
  inventory(run);
  run(`
    const [first, second] = state.projects;
    first.repository_urls = ['https://github.com/owner/one', 'https://github.com/owner/two'];
    first.local_path = '/checkout';
    first.findings[0].severity = first.findings[2].severity = 'CRITICAL';
    first.runs = [{status:'complete', count:99}];
    second.repository = 'https://github.com/owner/legacy';
    filter.severity = 'LOW';
    location.hash = '#projects';
    render();
  `);
  const projectRows = run(`$('#main').innerHTML`).split('<div class="project-list-row">').slice(1);
  assert.match(projectRows[0], /<span>2 components<\/span><span>2 repository URLs<\/span><span class="pill critical">Critical 2<\/span>/);
  assert.match(projectRows[1], /<span>1 repository URL<\/span><span class="pill ">Critical 0<\/span>/);

  run(`second.repository_urls = []; second.local_path = '/checkout';`);
  assert.doesNotMatch(run('projectList([second], true)'), /repository URL/);
  assert.doesNotMatch(run('projectList([first])'), /project-list-summary/);
  run(`lang = 'ja'; first.findings = Array.from({length:1001}, () => ({severity:'CRITICAL'}));`);
  assert.match(run('projectList([first], true)'), /リポジトリ URL 2 件<\/span><span class="pill critical">緊急 1,001<\/span>/);
});

test('Edit project opens a dedicated deletion page and cancelling restores the draft', async () => {
  const run = app();
  inventory(run);
  run(`
    var mounts = [];
    mountProjectForm = (container, draft) => mounts.push(draft);
    projectFormValues = () => ({name:'Unsaved name'});
    location.hash = '#project/p/edit';
    renderProjectEditor('p');
  `);
  assert.match(run(`$('#main').innerHTML`), /delete-project-button" data-action="delete-project" data-id="p"/);
  await run(`
    const editor = $('#project-editor form');
    editor.dataset = {projectId:'p', revision:'4', language:'en'};
    editor.querySelector = () => ({disabled:false});
    const remove = {dataset:{action:'delete-project', id:'p'}, closest:selector => selector === '[data-action]' ? remove : null};
    document.listeners.click({target:remove});
  `);
  assert.equal(run('location.hash'), 'project/p/delete');
  run(`
    editor.dataset = {};
    const cancel = {dataset:{action:'cancel-project-deletion'}, closest:selector => (
      selector === '[data-action]' ? cancel : selector === 'form' ? {dataset:{projectId:'p'}} : null
    )};
  `);
  await run('document.listeners.click({target:cancel})');
  assert.equal(run('location.hash'), 'project/p/edit');
  run(`location.hash = '#project/p/edit'; window.listeners.hashchange();`);
  assert.equal(run('mounts[1].name'), 'Unsaved name');
  assert.equal(run('mounts[1].revision'), '4');
});

test('project deletion requires an exact name and handles an active assessment and request failure', async () => {
  const calls = [];
  let fail = true;
  const run = app(async (...args) => {
    calls.push(args);
    if (fail) throw new Error('Delete failed');
  });
  inventory(run);
  run(`
    location.hash = '#project/p/delete';
    state.projects[0].name = 'P <&> 型';
    var confirmForm = $('#delete-project-form');
    var input = {value:'', addEventListener(type, listener){this[type]=listener;}, focus(){ this.focused = true; }};
    var submit = {}, busy = {}, cancel = {}, error = {};
    confirmForm.dataset = {};
    confirmForm.elements = {confirmation:input};
    confirmForm.querySelector = selector => ({
      '[data-delete-project-submit]':submit, '[data-delete-project-busy]':busy,
      '[data-action="cancel-project-deletion"]':cancel, '[data-delete-project-error]':error,
    })[selector];
    toast = () => {};
    render();
    Object.assign(confirmForm.dataset,{projectId:'p',projectName:state.projects[0].name,language:'en'});
    var submitDeletion = () => confirmForm.listeners.submit({preventDefault(){},target:confirmForm});
  `);
  const html = run(`$('#main').innerHTML`);
  assert.match(html, /<h1>Delete project<\/h1>/);
  assert.match(html, /<strong>P &lt;&amp;&gt; 型<\/strong>/);
  assert.match(html, /data-delete-project-submit disabled/);
  assert.equal(run('input.focused'), true);
  run(`input.value='p <&> 型'; input.input();`);
  assert.equal(run('submit.disabled'), true);
  await run('submitDeletion()');
  assert.deepEqual(calls, []);
  run(`input.value='P <&> 型'; input.input();`);
  assert.equal(run('submit.disabled'), false);
  run(`applyPollingState({...state,projects:[{...state.projects[0],syncing:true},state.projects[1]]});`);
  assert.equal(run('submit.disabled'), true);
  assert.equal(run('busy.hidden'), false);
  await run('submitDeletion()');
  assert.deepEqual(calls, []);
  run(`applyPollingState({...state,projects:[{...state.projects[0],syncing:false},state.projects[1]]});`);
  assert.equal(run('submit.disabled'), false);
  assert.equal(run('input.value'), 'P <&> 型');
  await run('submitDeletion()');
  assert.equal(run('error.textContent'), 'Delete failed');
  assert.equal(run('submit.disabled'), false);
  fail = false;
  await run('Promise.all([submitDeletion(), submitDeletion()])');
  assert.deepEqual(calls, [
    ['main.Desktop.DeleteProject','p','P <&> 型'],
    ['main.Desktop.DeleteProject','p','P <&> 型'],
  ]);
  assert.equal(run('location.hash'), 'projects');
  assert.equal(run(`state.projects.map(p => p.id).join(',')`), 'q');
});

test('component Critical counts isolate project and asset IDs from duplicate names, scanner results, and display filters',()=>{
  const run=app();inventory(run);
  run(`state.projects[0].assets.push({id:'second-demo',kind:'library',name:'demo',version:'2'});state.projects[0].findings.push({id:'CVE-C1',asset_id:'shared',severity:'CRITICAL'},{id:'CVE-C2',asset_id:'shared',severity:'CRITICAL'},{id:'CVE-C3',asset_id:'second-demo',severity:'CRITICAL'},{id:'CVE-CS',asset_id:'code:lib',severity:'CRITICAL'});state.projects[1].findings.push({id:'CVE-CQ',asset_id:'shared',severity:'CRITICAL'});filter={search:'no results',severity:'LOW',stack:'other',project:'q',match:'scanner'};projectTab='techStack';renderProject('p')`);
  const html=run(`document.querySelector('#project-tab-content').innerHTML`);
  const counts=[...html.matchAll(/class="stack-critical-count"><span>Critical<\/span><span class="pill ([^"]*)">(\d+)<\/span>/g)].map(m=>({style:m[1],count:Number(m[2])}));
  assert.deepEqual(counts,[{style:'critical',count:2},{style:'',count:0},{style:'critical',count:1}]);
  run(`renderProject('q')`);
  assert.match(run(`document.querySelector('#project-tab-content').innerHTML`),/class="stack-critical-count"><span>Critical<\/span><span class="pill critical">1<\/span>/);
});

test('component Critical counts handle missing findings, Japanese labels, and refreshed assessments',()=>{
  const run=app();inventory(run);
  run(`projectTab='techStack';delete state.projects[0].findings;renderProject('p')`);
  assert.match(run(`document.querySelector('#project-tab-content').innerHTML`),/class="stack-critical-count"><span>Critical<\/span><span class="pill ">0<\/span>/);
  run(`lang='ja';state.projects[0].findings=[{id:'CVE-C',asset_id:'shared',severity:'CRITICAL'}];renderProject('p')`);
  assert.match(run(`document.querySelector('#project-tab-content').innerHTML`),/class="stack-critical-count"><span>緊急<\/span><span class="pill critical">1<\/span>/);
  run(`state.projects[0].findings[0].severity='HIGH';renderProject('p')`);
  assert.doesNotMatch(run(`document.querySelector('#project-tab-content').innerHTML`),/class="pill critical"/);
});

test('each component defaults to all severities independently of the project selection',()=>{
  const run=app();inventory(run);run(`syncSeveritySelection.p='CRITICAL';projectTab='techStack';renderProject('p')`);
  const html=run(`document.querySelector('#project-tab-content').innerHTML`);
  const selects=[...html.matchAll(/<select data-sync-component-severity[\s\S]*?<\/select>/g)].map(m=>m[0]);
  assert.equal(selects.length,2);
  for(const select of selects){
    assert.match(select,/<option value="">All severities<\/option>/);
    assert.doesNotMatch(select,/<option[^>]* selected/);
    assert.match(select,/value="UNKNOWN"[^>]*>Unrated/);
  }
});

test('component severity changes survive redraws and stay isolated across components and projects',()=>{
  const run=app();inventory(run);
  run(`var select={value:'HIGH',dataset:{projectId:'p',assetId:'shared'},matches:selector=>selector==='[data-sync-component-severity]'};document.listeners.change({target:select});projectTab='techStack';renderProject('p')`);
  assert.match(run(`componentSyncControls(state.projects[0],state.projects[0].assets[0])`),/value="HIGH" selected>High/);
  assert.doesNotMatch(run(`componentSyncControls(state.projects[0],state.projects[0].assets[1])`),/<option[^>]* selected/);
  assert.doesNotMatch(run(`componentSyncControls(state.projects[1],state.projects[1].assets[0])`),/<option[^>]* selected/);
  run(`renderProject('q');renderProject('p')`);
  assert.match(run(`document.querySelector('#project-tab-content').innerHTML`),/value="HIGH" selected>High/);
  run(`select.value='';document.listeners.change({target:select})`);
  assert.doesNotMatch(run(`componentSyncControls(state.projects[0],state.projects[0].assets[0])`),/<option[^>]* selected/);
});

test('component Sync now sends that card severity and resetting to all omits the severity restriction',async()=>{
  const run=app();inventory(run);
  run(`var calls=[];invoke=async(...args)=>calls.push(args);refresh=async()=>{};toast=()=>{};syncSeveritySelection.p='HIGH';componentSyncSeveritySelection.set(stackKey('p','shared'),'CRITICAL');var target={dataset:{action:'sync-asset',id:'p',asset:'shared'},closest:selector=>selector==='[data-action]'?target:null}`);
  await run(`document.listeners.click({target})`);
  run(`componentSyncSeveritySelection.set(stackKey('p','shared'),'')`);
  await run(`document.listeners.click({target})`);
  assert.deepEqual(JSON.parse(run('JSON.stringify(calls)')),[
    ['Sync','p',{asset_id:'shared',severity:'CRITICAL'}],
    ['Sync','p',{asset_id:'shared'}]
  ]);
});

test('component severity controls localize, escape identifiers, and disable while the project syncs',()=>{
  const run=app();inventory(run);run(`lang='ja';state.projects[0].syncing=true;state.projects[0].assets[0].id='\"<asset>'`);
  const html=run(`componentSyncControls(state.projects[0],state.projects[0].assets[0])`);
  assert.match(html,/深刻度別の同期/);assert.match(html,/value="">すべての深刻度/);
  assert.match(html,/data-asset-id="&quot;&lt;asset&gt;"/);
  assert.match(html,/<select[^>]+ disabled>/);assert.match(html,/<button[^>]+ disabled>/);
  assert.doesNotMatch(html,/<asset>/);
});

test('workflow controls offer Pause and Stop while running and Resume while paused or pausing',()=>{
  const run=app();workflowFixture(run);
  let html=run('workflowBody(project,workflow)');
  assert.match(html,/data-control="pause"[^>]*>Pause/);assert.match(html,/data-control="stop"[^>]*>Stop/);
  for(const status of ['pausing','paused']){
    run(`workflow.status=${JSON.stringify(status)}`);html=run('workflowBody(project,workflow)');
    assert.match(html,/data-control="resume"[^>]*>Resume/);assert.match(html,/data-control="stop"/);
    assert.doesNotMatch(html,/data-control="pause"/);
    assert.match(html,status==='paused'?/This workflow is paused/:/Waiting for the current request or scanner/);
  }
  run(`workflow.status='stopping'`);html=run('workflowBody(project,workflow)');
  assert.match(html,/data-control="stop"[^>]* disabled>Stop/);
  assert.doesNotMatch(html,/data-control="pause"|data-control="resume"/);
  for(const status of ['complete','partial','failed','interrupted','stopped']){
    run(`workflow.status=${JSON.stringify(status)}`);
    assert.doesNotMatch(run('workflowBody(project,workflow)'),/data-action="control-sync"/);
  }
  run(`workflow.status='paused';lang='ja'`);
  assert.match(run('workflowBody(project,workflow)'),/>再開<\/button>/);
  assert.match(run('workflowBody(project,workflow)'),/>停止<\/button>/);
});

test('workflow control requests target the exact run and Stop needs confirmation',async()=>{
  const run=app();workflowFixture(run);
  run(`var calls=[],refreshes=0;filter.search='keep';invoke=async(...args)=>calls.push(args);refresh=async()=>refreshes++;toast=()=>{};confirmAction=()=>false`);
  assert.equal(await run(`controlWorkflow('p','run-1','stop')`),false);
  assert.equal(run('calls.length'),0);
  await run(`controlWorkflow('p','run-1','pause')`);
  await run(`controlWorkflow('p','run-1','resume')`);
  run(`confirmAction=()=>true`);await run(`controlWorkflow('p','run-1','stop')`);
  assert.deepEqual(JSON.parse(run('JSON.stringify(calls)')),[
    ['ControlRun','p','run-1','pause'],
    ['ControlRun','p','run-1','resume'],
    ['ControlRun','p','run-1','stop']
  ]);
  assert.equal(run('refreshes'),3);assert.equal(run('filter.search'),'keep');
  run(`invoke=async()=>{throw new Error('Run already finished')}`);
  await assert.rejects(run(`controlWorkflow('p','run-1','pause')`),/Run already finished/);
  assert.equal(run('refreshes'),3);
});

test('paused workflows freeze active elapsed time and remain protected; stopped runs can be closed or deleted',()=>{
  const run=app();workflowFixture(run);
  run(`workflow.status='paused';workflow.started_at='2026-11-15T10:00:00Z';workflow.paused_at='2026-11-15T10:02:00Z';workflow.paused_seconds=30`);
  assert.equal(run('workflowElapsed(workflow)'),'1m 30s');
  assert.equal(run('canDismissWorkflow(workflow)'),false);assert.equal(run('canDeleteActivity(workflow)'),false);
  assert.match(run(`projectStatus({syncing:true,runs:[workflow]})`),/Paused/);
  run(`state={projects:[{...project,assets:[],findings:[],schedule:'off',syncing:true,runs:[workflow]}]};renderProject('p')`);
  const projectHTML=run(`document.querySelector('#main').innerHTML`);
  assert.equal((projectHTML.match(/>Paused<\/span>/g)||[]).length,1);
  assert.match(projectHTML,/class="workflow-actions"><span class="pill paused">Paused<\/span><button[^>]+data-control="resume"/);
  run(`workflow.status='stopped';workflow.paused_at='0001-01-01T00:00:00Z';workflow.finished_at='2026-11-15T10:05:00Z';workflow.paused_seconds=120`);
  assert.equal(run('workflowElapsed(workflow)'),'3m 0s');
  assert.equal(run('canDismissWorkflow(workflow)'),true);assert.equal(run('canDeleteActivity(workflow)'),true);
  assert.match(run('workflowRun(project,workflow,true)'),/data-dismiss-workflow="run-1"/);
});

test('workflow controls recover their enabled state when a control request fails',async()=>{
  const run=app();workflowFixture(run);
  run(`var errorShown='';invoke=async()=>{throw new Error('Workflow already finished')};toast=message=>errorShown=message;var target={dataset:{action:'control-sync',control:'pause',id:'p',run:'run-1'},closest:selector=>selector==='[data-action]'?target:null}`);
  await run(`document.listeners.click({target})`);
  assert.equal(run('target.disabled'),false);assert.equal(run('errorShown'),'Workflow already finished');
});

test('partial workflows keep the short badge and show a localized completion message',()=>{
  const run=app();workflowFixture(run);
  run(`workflow.status='partial';workflow.steps.forEach(step=>step.status='complete')`);
  const html=run('workflowBody(project,workflow)');
  assert.match(html,/<span class="pill partial">Partial<\/span>/);
  assert.match(html,/<div class="workflow-current" role="status">Assessment completed partially<\/div>/);
  run(`lang='ja'`);
  assert.match(run('workflowBody(project,workflow)'),/role="status">評価は一部のみ完了しました<\/div>/);
});

test('polling preserves paused and finished workflow panels until their details are toggled',()=>{
  for (const status of ['paused', 'partial']) {
    const run=app();workflowFixture(run);
    run(`workflow.status=${JSON.stringify(status)};state={projects:[{...project,runs:[workflow]}]};var panel={dataset:{syncProjectId:'p',syncRun:'run-1'},innerHTML:'existing DOM'};document.querySelectorAll=()=>[panel];updateSyncPanels()`);
    assert.equal(run('panel.innerHTML'),'existing DOM');
    run(`toggleWorkflow('run-1')`);
    assert.match(run('panel.innerHTML'),/Show less/);
  }
});
