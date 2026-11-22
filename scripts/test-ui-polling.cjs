const {test} = require('node:test');
const assert = require('node:assert/strict');
const {app} = require('./ui-test-harness.cjs');

function fixture(native) {
  const run=app(native);
  run(`
    location.hash='#vulnerabilities';
    state={version:'0:first',settings:{language:'en',sources:{},scanners:{}},cache_stats:{hits:1},projects:[
      {id:'p',name:'Project',revision:1,assets:[{id:'a',kind:'library',name:'Demo',version:'1'}],findings:[{id:'CVE-FIRST',asset_id:'a',component:'Demo',version:'1',title:'First advisory',severity:'HIGH',match:'package',sources:['OSV']}],runs:[
        {id:'active',status:'running',count:1,steps:[],logs:[]},
        {id:'history',status:'complete',count:4,steps:[],logs:[]},
      ]},
      {id:'q',name:'Other project',assets:[],findings:[{id:'CVE-OTHER',title:'Other advisory',severity:'LOW',match:'review',sources:['NVD']}],runs:[]},
    ]};
    var renders=0,panels=0;var realUpdateSyncPanels=updateSyncPanels;render=()=>renders++;localize=()=>{};updateSyncPanels=()=>panels++;updateDatabaseFreshnessWarning=()=>{};updateCacheMetrics=()=>{};
    var findingArray=state.projects[0].findings,history=state.projects[0].runs[1],other=state.projects[1];
    $('#finding-results').innerHTML=findingsTable();
    var delta={base_version:'0:first',version:'0:second',cache_stats:{hits:2},delta:{projects:[{id:'p',workflows:{order:['active','history'],updated:[{index:0,run:{id:'active',status:'running',count:1,steps:[{status:'running'}],logs:[{event:'page'}]}}]}}]}};
  `);
  return run;
}

const ids=html=>[...html.matchAll(/data-finding="([^"]+)"/g)].map(item=>item[1]);

test('incremental progress retains findings, history, search indexes, filters and pagination',()=>{
  const run=fixture();
  run("filter.search='first';findingsPage=3;var query=queryFindings();var input=$('#finding-search');input.draft='keep typing'");
  assert.equal(run('applyPollingState(delta)'),true);
  assert.equal(run('state.version'),'0:second');
  assert.equal(run('state.projects[0].findings===findingArray'),true);
  assert.equal(run('state.projects[0].runs[1]===history'),true);
  assert.equal(run('state.projects[1]===other'),true);
  assert.equal(run('queryFindings()===query'),true);
  assert.equal(run('state.projects[0].runs[0].logs.length'),1);
  assert.equal(run('filter.search'),'first');
  assert.equal(run('findingsPage'),3);
  assert.equal(run("$('#finding-search').draft"),'keep typing');
  assert.equal(run('renders'),0);
  assert.equal(run('panels'),1);
});

test('workflow counts and status update panels without rebuilding vulnerability pages',()=>{
  const run=fixture();
  run("delta.delta.projects[0].workflows.updated[0].run.count=8;delta.delta.projects[0].workflows.updated[0].run.status='paused'");
  run('applyPollingState(delta)');
  assert.equal(run('renders'),0);
  assert.equal(run('state.projects[0].runs[0].count'),8);
  assert.equal(run('state.projects[0].runs[0].status'),'paused');
  for(const route of ['#activity','#overview','#projects','#project/p']) {
    const activity=fixture();
    activity(`location.hash=${JSON.stringify(route)};projectTab='activity';delta.delta.projects[0].workflows.updated[0].run.count=8;applyPollingState(delta)`);
    assert.equal(activity('renders'),1,route);
  }
});

test('changed paused and finished workflow panels repaint once without rebuilding the findings table',()=>{
  for(const status of ['paused','complete','partial','failed','interrupted','stopped']) {
    const run=fixture();
    run(`
      var panel=$('#fixture-workflow');
      panel.dataset={syncProjectId:'p',syncRun:'active',workflowDismissible:'true',workflowNotices:'true'};
      const originalQueryAll=document.querySelectorAll.bind(document);
      document.querySelectorAll=selector=>selector==='[data-sync-run]'?[panel]:originalQueryAll(selector);
      updateSyncPanels=realUpdateSyncPanels;
      delta.delta.projects[0].workflows.updated[0].run.status=${JSON.stringify(status)};
      applyPollingState(delta);
    `);
    assert.equal(run('renders'),0,status);
    assert.equal(run('panel.className'),'sync-workflow '+status,status);
    assert.match(run('panel.innerHTML'),new RegExp('pill '+status),status);
    run("panel.innerHTML='unchanged terminal panel';delta.base_version=state.version;delta.version+='next';delta.delta={};applyPollingState(delta)");
    assert.equal(run('panel.innerHTML'),'unchanged terminal panel',status);
  }
});

test('metadata patches preserve omitted finding and run data while changing project labels',()=>{
  const run=fixture();
  run(`delta.delta.projects=[{id:'p',metadata:{id:'p',name:'Renamed project',revision:2,findings:null,runs:null}}];applyPollingState(delta)`);
  assert.equal(run('state.projects[0].name'),'Renamed project');
  assert.equal(run('state.projects[0].findings===findingArray'),true);
  assert.equal(run('state.projects[0].runs[1]===history'),true);
  assert.equal(run('renders'),1);
  assert.match(run('findingsTable()'),/Renamed project/);
});

test('finding patches refresh severity and search results, including empty and null results',()=>{
  const run=fixture();
  run(`
    delta.delta.projects=[{id:'p',findings:[{id:'CVE-NEW',asset_id:'a',title:'Replacement',component:'Demo',severity:'CRITICAL',match:'package',sources:['OSV']}]}];
    applyPollingState(delta);filter.stack=[stackKey('p','a')];
  `);
  assert.deepEqual(ids(run('findingsTable()')),['CVE-NEW']);
  assert.match(run('findingsTable()'),/Critical <strong>1<\/strong>/);
  for(const value of ['[]','null']) {
    run(`delta.base_version=state.version;delta.version+='next';delta.delta.projects[0].findings=${value};applyPollingState(delta)`);
    assert.deepEqual(ids(run('findingsTable()')),[]);
    assert.match(run('findingsTable()'),/Critical <strong>0<\/strong>/);
  }
});

test('workflow slot patches remove history and handle duplicate legacy run IDs without borrowing data',()=>{
  const run=fixture();
  run(`delta.delta.projects[0].workflows={order:['history'],updated:[{index:0,run:{...history,count:9}}]};applyPollingState(delta)`);
  assert.equal(run('state.projects[0].runs.length'),1);
  assert.equal(run('state.projects[0].runs[0].id'),'history');
  assert.equal(run('state.projects[0].runs[0].count'),9);
  run(`
    state.projects[0].runs=[{id:'legacy',count:2},{id:'legacy',count:3}];
    delta.base_version=state.version;delta.version+='next';
    delta.delta.projects[0].workflows={order:['legacy','legacy'],updated:[{index:1,run:{id:'legacy',count:4}}]};
    applyPollingState(delta);
  `);
  assert.equal(run('state.projects[0].runs[0].count'),2);
  assert.equal(run('state.projects[0].runs[1].count'),4);
});

test('project additions and deletions merge atomically in the supplied order',()=>{
  const run=fixture();
  run(`delta.delta={project_order:['new','q'],projects:[{id:'new',metadata:{id:'new',name:'New project',assets:[],findings:null,runs:null},findings:[],workflows:{order:[],updated:[]}}]};applyPollingState(delta)`);
  assert.equal(run("state.projects.map(project=>project.id).join(',')"),'new,q');
  assert.equal(run('state.projects[1]===other'),true);
  assert.deepEqual(ids(run('findingsTable()')),['CVE-OTHER']);
  run("delta.base_version=state.version;delta.version+='next';delta.delta={project_order:[]};applyPollingState(delta)");
  assert.equal(run('state.projects.length'),0);
});

test('stale and invalid deltas change neither data nor cache/catalogue metrics',()=>{
  for(const mutate of [
    "delta.base_version='old'",
    "delta.delta=[]",
    "delta.delta.settings=[]",
    "delta.delta.projects[0].workflows.updated[0].index=9",
    "delta.delta.projects[0].workflows.updated[0].run.id='wrong'",
    "delta.delta.project_order=['missing']",
    "delta.delta.project_order=['p','p']",
    "delta.delta.projects.push(delta.delta.projects[0])",
    "delta.delta.projects=[{id:'unknown',findings:[]}]",
    "delta.delta.projects=[{id:'p',findings:{invalid:true}}]",
  ]) {
    const run=fixture();
    run(`var original=state;delta.cve_database={records:999};${mutate}`);
    assert.equal(run('applyPollingState(delta)'),false,mutate);
    assert.equal(run('state===original'),true);
    assert.equal(run('state.cache_stats.hits'),1);
    assert.equal(run('state.cve_database'),undefined);
  }
});

test('settings and editor drafts survive deltas while saved credential status can be cleared',()=>{
  const run=fixture();
  run(`
    location.hash='#settings';$('#settings-form').draft='unsaved API input';
    state.token_status={openai:true};state.saved_token_status={openai:true};
    delta.metadata_changed=true;delta.scan_repositories={};delta.token_status={};delta.saved_token_status={};
    delta.delta.settings={language:'ja',sources:{},scanners:{}};
    applyPollingState(delta);
  `);
  assert.equal(run("$('#settings-form').draft"),'unsaved API input');
  assert.equal(run('state.settings.language'),'en');
  assert.equal(run('Object.keys(state.token_status).length'),0);
  assert.equal(run('renders'),0);
  run(`location.hash='#project/p/edit';$('#project-editor').draft='unsaved project';delta.base_version=state.version;delta.version+='next';delta.delta={projects:[{id:'p',metadata:{id:'p',name:'Changed',revision:2,findings:null,runs:null}}]};applyPollingState(delta)`);
  assert.equal(run("$('#project-editor').draft"),'unsaved project');
  assert.equal(run('state.projects[0].revision'),2);
  assert.equal(run('renders'),0);
});

test('idle deltas advance the cursor without replacing finding arrays or rebuilding pages',()=>{
  const run=fixture();
  run('delta.delta={};applyPollingState(delta)');
  assert.equal(run('state.version'),'0:second');
  assert.equal(run('state.projects[0].findings===findingArray'),true);
  assert.equal(run('renders'),0);
});

test('incremental progress preserves a pending debounced search',()=>{
  const run=fixture();
  run(`bindFilters();$('#finding-search').listeners.input({target:{value:'first'}});applyPollingState(delta);advanceTimers(120)`);
  assert.equal(run('filter.search'),'first');
  assert.deepEqual(ids(run("$('#finding-results').innerHTML")),['CVE-FIRST']);
  assert.equal(run('renders'),0);
});

test('polling requests a full snapshot after an invalid delta and fences the fallback against workspace switches',async()=>{
  const calls=[];
  const run=fixture(async method=>{
    calls.push(method);
    if(method==='main.Desktop.StateSince')return {base_version:'unknown',version:'new',delta:{}};
    return {version:'reset',settings:{language:'en'},projects:[{id:'reset',assets:[],findings:[],runs:[]}]};
  });
  run(`const originalQuery=document.querySelector.bind(document);document.querySelector=selector=>selector==='dialog[open]'?null:originalQuery(selector)`);
  await run('pollState()');
  assert.deepEqual(calls,['main.Desktop.StateSince','main.Desktop.State']);
  assert.equal(run('state.projects[0].id'),'reset');

  let resolve;
  const switched=fixture(()=>new Promise(done=>{resolve=done;}));
  switched(`const originalQuery=document.querySelector.bind(document);document.querySelector=selector=>selector==='dialog[open]'?null:originalQuery(selector)`);
  const pending=switched('pollState()');
  switched("state={...state,version:'1:other',projects:[]}");
  resolve({base_version:'0:first',version:'0:second',delta:{project_order:[]}});
  await pending;
  assert.equal(switched('state.version'),'1:other');
  assert.equal(switched('state.projects.length'),0);
});
