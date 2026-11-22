// Synthetic Node/VM timings, excluding WebView layout, bridge transfer, and I/O.
// Optional argument: an earlier app.js snapshot for a like-for-like comparison.
const assert = require('node:assert/strict');
const path = require('node:path');
const {performance} = require('node:perf_hooks');
const {app} = require('./ui-test-harness.cjs');

const source = path.resolve(process.argv[2] || path.join(__dirname, '../cmd/vulman/ui/app.js'));
const samples = 15;

function measure(run, prepare, expression) {
  const timings = [];
  for (let i = 0; i < samples + 3; i++) {
    if (prepare) run(prepare);
    const start = performance.now();
    run(expression);
    const elapsed = performance.now() - start;
    if (i >= 3) timings.push(elapsed);
  }
  timings.sort((a, b) => a - b);
  return {median_ms:+timings[Math.floor(samples / 2)].toFixed(3), p95_ms:+timings[Math.ceil(samples * 0.95) - 1].toFixed(3)};
}

console.log(JSON.stringify({node:process.version, platform:process.platform, arch:process.arch, source, samples, synthetic:true}));
for (const count of [1000, 10000, 50000]) {
  const run = app(undefined, source);
  run(`
    location.hash = '#vulnerabilities';
    const fixture = {version:'1',settings:{language:'en'},projects:[{
      id:'synthetic',name:'Synthetic benchmark project',assets:[{id:'demo',name:'Example component',version:'1.0'}],
      runs:[{id:'benchmark',status:'running',steps:[],logs:[]}],
      findings:Array.from({length:${count}}, (_,i) => ({
        id:'CVE-2026-'+i,asset_id:'demo',title:'Example dependency vulnerability with affected version constraints',
        component:'Example component',version:'1.0',description:'Synthetic advisory description with affected version details. '.repeat(4),
        severity:['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'][i%5],sources:['NVD','CVE'],references:['https://example.com/advisory'],match:'review',
      })),
    }]};
    state = JSON.parse(JSON.stringify(fixture));
    render = () => {}; localize = () => {}; updateSyncPanels = () => {}; updateDatabaseFreshnessWarning = () => {};
    var next, searchSequence = 0, deltaSequence = 0;
  `);
  const polling = measure(run,
    "next=JSON.parse(JSON.stringify(fixture));next.projects[0].runs[0].logs.push({event:'page'});",
    'applyPollingState(next)');
  const incrementalPolling = run("typeof applyWorkspaceDelta === 'function'") ? measure(run,
    "next={base_version:state.version,version:'incremental-'+(++deltaSequence),delta:{projects:[{id:'synthetic',workflows:{order:['benchmark'],updated:[{index:0,run:{...state.projects[0].runs[0],logs:[{event:'page'}]}}]}}]}};",
    'applyPollingState(next)') : null;
  const firstTable = measure(run,
    "state=JSON.parse(JSON.stringify(fixture));filter={search:'',severity:'',project:'',match:'',stack:''};",
    'findingsTable()');
  const repeatedTable = measure(run, '', 'findingsTable()');
  const firstSearch = measure(run,
    "state=JSON.parse(JSON.stringify(fixture));filter={search:'dependency',severity:'',project:'',match:'',stack:''};",
    'findingsTable()');
  const search = measure(run,
    "filter.search=['example','dependency','vulnerability'][searchSequence++%3];",
    'findingsTable()');
  const pagination = measure(run, 'findingsPage=findingsPage===1?2:1;', 'findingsTable()');
  assert.equal(run('(findingsTable().match(/<tr data-finding=/g)||[]).length'), 100);
  console.log(JSON.stringify({findings:count,polling,incrementalPolling,firstTable,repeatedTable,firstSearch,search,pagination,renderedRows:100}));
}
