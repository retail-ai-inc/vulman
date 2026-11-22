const {test} = require('node:test');
const assert = require('node:assert/strict');
const {app} = require('./ui-test-harness.cjs');

function fixture() {
  const run = app();
  run(`
    location.hash='#vulnerabilities';
    state={version:'1:1',data_directory:'/fixture/one',settings:{language:'en'},projects:[
      {id:'p',name:'First project',assets:[],runs:[{id:'run',status:'running',steps:[],logs:[]}],findings:[
        {id:'CVE-HIGH',asset_id:'a',component:'Demo',title:'First advisory',description:'Original description',severity:'HIGH',match:'package',sources:['OSV'],references:['https://example.com/first']},
        {id:'CVE-CRITICAL',asset_id:'a',component:'Demo',title:'緊急の問題',severity:'CRITICAL',match:'package',sources:['OSV']},
        {id:'CVE-LOW',asset_id:'b',component:'Other',title:'Other advisory',severity:'LOW',match:'review',sources:['NVD']},
      ]},
      {id:'q',name:'Second project',assets:[],runs:[],findings:[
        {id:'CVE-SECOND',asset_id:'a',component:'Demo',title:'Second advisory',severity:'HIGH',match:'scanner',sources:['Trivy']},
      ]},
    ]};
    var pageRenders=0,panelUpdates=0;
    render=()=>pageRenders++;localize=()=>{};updateSyncPanels=()=>panelUpdates++;updateDatabaseFreshnessWarning=()=>{};
    $('#finding-results').innerHTML=findingsTable();
    var resultWrites=0,resultHTML=$('#finding-results').innerHTML;
    Object.defineProperty($('#finding-results'),'innerHTML',{get:()=>resultHTML,set:html=>{resultWrites++;resultHTML=html;}});
    bindFilters();
  `);
  return run;
}

const ids = html => [...html.matchAll(/data-finding="([^"]+)"/g)].map(match => match[1]);

test('progress polling reuses equal finding snapshots and cached queries without resetting filters or pagination', () => {
  const run = fixture();
  run(`
    filter.search='advisory';findingsPage=2;
    var original=state.projects[0].findings,query=queryFindings();
    var next=JSON.parse(JSON.stringify(state));
    next.version='1:2';next.projects[0].runs[0].logs.push({event:'page'});
    applyPollingState(next);
  `);
  assert.equal(run('pageRenders'), 0);
  assert.equal(run('panelUpdates'), 1);
  assert.equal(run('state.projects[0].findings===original'), true);
  assert.equal(run('queryFindings()===query'), true);
  assert.equal(run('filter.search'), 'advisory');
  assert.equal(run('findingsPage'), 2);
});

test('polling detects changed detail fields, aliases, provenance, and future finding fields even when counts stay equal', () => {
  for (const patch of [
    {description:'Updated description'}, {references:['https://example.com/updated']},
    {sources:['NVD','CVE']}, {aliases:['GHSA-demo']}, {fixed_versions:['2.0']},
    {generated_lockfile:true}, {scan_path:'new/project'}, {severity:'CRITICAL'},
    {future_field:{value:'new metadata'}}, {title:'Changed advisory'},
  ]) {
    const run = fixture();
    run(`
      var original=state.projects[0].findings;
      var next=JSON.parse(JSON.stringify(state));
      Object.assign(next.projects[0].findings[0],${JSON.stringify(patch)});
      applyPollingState(next);
    `);
    assert.equal(run('pageRenders'), 1, JSON.stringify(patch));
    assert.equal(run('state.projects[0].findings===original'), false);
    const saved=JSON.parse(run('JSON.stringify(state.projects[0].findings[0])'));
    for (const [key,value] of Object.entries(patch)) assert.deepEqual(saved[key],value);
  }
});

test('equal snapshots ignore object property order but preserve array order and missing fields', () => {
  const run = fixture();
  run(`
    var original=state.projects[0].findings;
    var next=JSON.parse(JSON.stringify(state));
    next.projects[0].findings[0]=Object.fromEntries(Object.entries(next.projects[0].findings[0]).reverse());
    applyPollingState(next);
  `);
  assert.equal(run('state.projects[0].findings===original'), true);
  run(`next=JSON.parse(JSON.stringify(state));delete next.projects[0].findings[0].description;applyPollingState(next)`);
  assert.equal(run('pageRenders'), 1);
  run(`next=JSON.parse(JSON.stringify(state));next.projects[0].findings.reverse();applyPollingState(next)`);
  assert.equal(run('pageRenders'), 2);
});

test('severity ordering is stable across projects and cached pages normalize unrated findings last', () => {
  const run = fixture();
  run(`state.projects[0].findings=[...state.projects[0].findings,{id:'CVE-UNRATED',severity:'unrecognized',sources:[]}];`);
  assert.deepEqual(ids(run('findingsTable()')), ['CVE-CRITICAL','CVE-HIGH','CVE-SECOND','CVE-LOW','CVE-UNRATED']);
  assert.deepEqual(ids(run("findingsTable('p')")), ['CVE-CRITICAL','CVE-HIGH','CVE-LOW','CVE-UNRATED']);
  run("filter.severity='UNKNOWN'");
  assert.deepEqual(ids(run('findingsTable()')), ['CVE-UNRATED']);
});

test('fresh finding arrays invalidate searches and severity counts after an assessment', () => {
  const run = fixture();
  run("filter.search='replacement';findingsTable();var next=JSON.parse(JSON.stringify(state));");
  run(`next.projects[0].findings=[{id:'CVE-NEW',asset_id:'a',title:'Replacement advisory',component:'New',severity:'CRITICAL',match:'package',sources:['OSV']}];applyPollingState(next)`);
  assert.deepEqual(ids(run('findingsTable()')), ['CVE-NEW']);
  assert.match(run('findingsTable()'), /1 match \(2 total\)/);
  run("filter.stack=[stackKey('p','a')]");
  assert.match(run('findingsTable()'), /Critical <strong>1<\/strong>/);
  run("state.projects[0].findings=[]");
  assert.match(run('findingsTable()'), /Critical <strong>0<\/strong>/);
});

test('query caching follows workspace, project, language, and repository attribution changes', () => {
  const run = fixture();
  run(`
    state.scan_repositories={p:[{key:'remote:first',label:'github.com/owner/demo'}]};
    state.projects[0].findings=[{id:'CVE-LEGACY',asset_id:'code:legacy',scan_repository:'github.com/owner/demo',title:'Legacy scanner result',severity:'HIGH',match:'scanner',sources:['Trivy']}];
    filter.stack=[scanLocationKey('p','remote:first')];
  `);
  assert.deepEqual(ids(run('findingsTable()')), ['CVE-LEGACY']);
  run("state.scan_repositories.p.push({key:'remote:second',label:'github.com/owner/demo'})");
  assert.deepEqual(ids(run('findingsTable()')), []);
  run("filter.stack='';state.projects[0].name='Renamed project';lang='ja'");
  assert.match(run('findingsTable()'), /Renamed project/);
  assert.match(run('findingsTable()'), /脆弱性/);
  run(`
    var next=JSON.parse(JSON.stringify(state));next.version='2:1';next.data_directory='/fixture/two';
    next.projects[0].findings=[{id:'CVE-NEW-WORKSPACE',title:'New workspace',severity:'LOW',sources:[]}];
    applyPollingState(next);
  `);
  const table=run('findingsTable()');
  assert.deepEqual(ids(table), ['CVE-SECOND','CVE-NEW-WORKSPACE']);
  assert.doesNotMatch(table,/CVE-LEGACY/);
});

test('search typing waits for a short pause and applies only the latest text once', () => {
  const run = fixture();
  run(`$('#finding-search').listeners.input({target:{value:'first'}});advanceTimers(80)`);
  assert.equal(run('resultWrites'), 0);
  run(`$('#finding-search').listeners.input({target:{value:'second'}});advanceTimers(119)`);
  assert.equal(run('resultWrites'), 0);
  run('advanceTimers(1)');
  assert.equal(run('resultWrites'), 1);
  assert.deepEqual(ids(run('resultHTML')), ['CVE-SECOND']);
});

test('clearing a query and pressing Enter apply results immediately without a second delayed render', () => {
  const run = fixture();
  run(`
    $('#finding-search').listeners.input({target:{value:'first'}});
    var prevented=0;
    $('#finding-search').listeners.keydown({key:'Enter',preventDefault(){prevented++;}});
  `);
  assert.equal(run('prevented'), 1);
  assert.deepEqual(ids(run('resultHTML')), ['CVE-HIGH']);
  run('advanceTimers(200)');
  assert.equal(run('resultWrites'), 1);
  run(`$('#finding-search').listeners.input({target:{value:''}})`);
  assert.equal(ids(run('resultHTML')).length, 4);
  assert.equal(run('resultWrites'), 2);
});

test('Japanese IME composition keeps intermediate input out of results until composition ends', () => {
  const run = fixture();
  run(`
    $('#finding-search').listeners.input({target:{value:'first'}});
    $('#finding-search').listeners.compositionstart();
    $('#finding-search').listeners.input({target:{value:'き'},isComposing:true});
    $('#finding-search').listeners.keydown({key:'Enter',isComposing:true,preventDefault(){throw new Error('IME Enter was intercepted');}});
    advanceTimers(200);
  `);
  assert.equal(run('resultWrites'), 0);
  run(`$('#finding-search').listeners.compositionend({target:{value:'緊急'}});advanceTimers(120)`);
  assert.deepEqual(ids(run('resultHTML')), ['CVE-CRITICAL']);
  assert.equal(run('resultWrites'), 1);
});

test('filter changes use the latest typed search and cancel pending search callbacks', () => {
  const run = fixture();
  run(`
    $('#finding-search').listeners.input({target:{value:'advisory'}});
    $('#severity-filter').listeners.change({target:{value:'LOW'}});
  `);
  assert.deepEqual(ids(run('resultHTML')), ['CVE-LOW']);
  run('advanceTimers(200)');
  assert.equal(run('resultWrites'), 1);
});

test('navigation and replaced search controls prevent delayed results from reaching another page', () => {
  const run = fixture();
  run(`
    $('#finding-search').listeners.input({target:{value:'first'}});
    location.hash='#settings';window.listeners.hashchange();advanceTimers(200);
  `);
  assert.equal(run('resultWrites'), 0);
  run(`
    location.hash='#vulnerabilities';bindFilters();
    $('#finding-search').listeners.input({target:{value:'second'}});
    $('#finding-search').isConnected=false;advanceTimers(200);
  `);
  assert.equal(run('resultWrites'), 0);
});

test('progress arriving during a pending search keeps its query and returns the latest matching findings', () => {
  const run = fixture();
  run(`
    $('#finding-search').listeners.input({target:{value:'first'}});
    var next=JSON.parse(JSON.stringify(state));next.projects[0].runs[0].logs.push({event:'page'});
    applyPollingState(next);advanceTimers(120);
  `);
  assert.equal(run('pageRenders'), 0);
  assert.equal(run('filter.search'), 'first');
  assert.deepEqual(ids(run('resultHTML')), ['CVE-HIGH']);
});

test('cached search terms and fresh results remain escaped when rendered', () => {
  const run = fixture();
  run(`state.projects[0].findings=[{id:'CVE-HTML',title:'<SCRIPT>advisory</SCRIPT>',component:'<IMG SRC="data:,test">',severity:'HIGH',sources:['OSV']}];filter.search='script';`);
  const table=run('findingsTable()');
  assert.deepEqual(ids(table), ['CVE-HTML']);
  assert.doesNotMatch(table,/<\/?(?:script|img)\b/i);
  assert.match(table,/&lt;SCRIPT&gt;/);
});
