const {test} = require('node:test');
const assert = require('node:assert/strict');
const {app} = require('./ui-test-harness.cjs');

function fixture() {
  const run = app();
  run(`
    document.documentElement={};
    state={settings:{language:'en'},projects:[{id:'p',name:'My project',findings:[],runs:[{
      id:'r',status:'partial',started_at:'2026-11-22T08:00:00Z',steps:[
        {id:'nvd:a',kind:'nvd',component:'Go 1.27',status:'failed',finished_at:'2026-11-22T08:01:00Z',progress:{found:3,cache_status:'stale'}},
        {id:'osv:a',kind:'osv',component:'Go 1.27',status:'complete',progress:{}},
        {id:'nvd:b',kind:'nvd',component:'PHP 8.3',status:'failed',progress:{}},
      ],logs:[
        {step_id:'nvd:a',event:'failed',detail:'Original NVD failure'},
        {step_id:'nvd:a',event:'cache_summary',detail:'stale'},
        {step_id:'nvd:b',event:'failed',detail:'Different component failure'},
      ],
    }]}]};
    var project=state.projects[0],workflow=project.runs[0],step=workflow.steps[0],opens=0,focused=0;
    var body={scrollTop:900,scrollHeight:1200,clientHeight:400,setAttribute(){},focus(){focused++;}};
    Object.assign($('#workflow-failure-dialog'),{
      querySelector:selector=>selector==='.dialog-body'?body:selector==='.close-dialog'?$('#fixture-close'):null,
      showModal(){opens++;this.open=true;},
    });
  `);
  return run;
}

test('only failed or interrupted step markers are accessible failure-detail buttons',()=>{
  const run=fixture();
  for(const status of ['failed','interrupted']) {
    run(`step.status=${JSON.stringify(status)}`);
    const html=run('workflowStepMarker(project,workflow,step,0)');
    assert.match(html,/<button type="button"[^]*data-step-failure/);
    assert.match(html,/data-project-id="p" data-run-id="r" data-step-index="0"/);
    assert.match(html,/aria-haspopup="dialog"[^]*aria-label="Show failure details for NIST NVD · Go 1.27"/);
    assert.doesNotMatch(html,/aria-hidden/);
  }
  for(const status of ['complete','running','pending','skipped','stopped']) {
    run(`step.status=${JSON.stringify(status)}`);
    assert.doesNotMatch(run('workflowStepMarker(project,workflow,step,0)'),/button|data-step-failure/);
  }
  run(`expandedRuns.add('r')`);
  assert.match(run('workflowBody(project,workflow)'),/data-step-failure[^]*data-step-index="2"/);
});

test('retained step failures take priority and translate when the dialog is opened',()=>{
  const run=fixture();
  run(`step.failure={code:'timeout',fallback:'ignored English fallback'}`);
  for(const language of ['en','ja']) {
    run(`lang=${JSON.stringify(language)}`);
    assert.equal(run(`showWorkflowStepFailure('p','r',0)`),true);
    assert.equal(run("$('#workflow-failure-reason').textContent"),run("t('error_timeout')"));
    assert.equal(run("$('#workflow-failure-step').textContent"),'NIST NVD · Go 1.27');
    assert.match(run("$('#workflow-failure-context').textContent"),/My project/);
    assert.match(run("$('#workflow-failure-progress').textContent"),/3/);
    assert.equal(run("$('#fixture-close')['aria-label']"),run("t('close')"));
    assert.equal(run('body.scrollTop'),0);
  }
  assert.equal(run('opens'),2);
  assert.equal(run('focused'),2);
});

test('legacy failures use only the latest matching step failure, including localized logs',()=>{
  const run=fixture();
  assert.equal(run('workflowStepFailure(workflow,step)'),'Original NVD failure');
  run(`workflow.logs.push({step_id:'nvd:a',event:'failed',message:{code:'timeout'}});lang='ja'`);
  assert.equal(run('workflowStepFailure(workflow,step)'),run("t('error_timeout')"));
  assert.equal(run('workflowStepFailure(workflow,workflow.steps[2])'),'Different component failure');
});

test('missing legacy reasons are stated clearly without borrowing unrelated workflow warnings',()=>{
  const run=fixture();
  run(`workflow.logs=workflow.logs.filter(entry=>entry.step_id!=='nvd:a');workflow.warnings=['Another source failed']`);
  assert.equal(run('workflowStepFailure(workflow,step)'),run("t('stepFailureUnavailable')"));
  run(`step.status='interrupted'`);
  assert.equal(run('workflowStepFailure(workflow,step)'),run("t('stepInterruptionUnavailable')"));
});

test('failure reasons and project metadata remain literal text, and marker attributes are escaped',()=>{
  const run=fixture();
  run(`
    step.failure={code:'new_error',fallback:'<SCRIPT>window.compromised=true</SCRIPT>\\n<img src=x onerror=alert(1)>'};
    project.name='<img src=x>';step.component='<b>component</b>';
    showWorkflowStepFailure('p','r',0);
  `);
  assert.equal(run("$('#workflow-failure-reason').textContent"),'<SCRIPT>window.compromised=true</SCRIPT>\n<img src=x onerror=alert(1)>');
  assert.equal(run("$('#workflow-failure-reason').innerHTML"),'');
  assert.match(run("$('#workflow-failure-step').textContent"),/<b>component<\/b>/);
  run(`project.id='p"<img>';workflow.id='r"<SCRIPT>'`);
  const html=run('workflowStepMarker(project,workflow,step,0)');
  assert.match(html,/data-project-id="p&quot;&lt;img&gt;"/);
  assert.match(html,/data-run-id="r&quot;&lt;SCRIPT&gt;"/);
});

test('invalid or no-longer-failed step references do not open a dialog',()=>{
  const run=fixture();
  for(const expression of [
    "showWorkflowStepFailure('missing','r',0)","showWorkflowStepFailure('p','missing',0)",
    "showWorkflowStepFailure('p','r',-1)","showWorkflowStepFailure('p','r',NaN)",
    "showWorkflowStepFailure('p','r',0.5)","showWorkflowStepFailure('p','r',99)",
    "showWorkflowStepFailure('p','r',1)",
  ]) assert.equal(run(expression),false,expression);
  assert.equal(run('opens'),0);
});

test('identical step and run IDs in other projects cannot supply the wrong failure reason',()=>{
  const run=fixture();
  run(`state.projects.push({id:'q',name:'Another project',runs:[{id:'r',steps:[{id:'nvd:a',kind:'nvd',status:'failed',failure:{code:'fixture',fallback:'Another project failure'}}]}]})`);
  assert.equal(run("showWorkflowStepFailure('q','r',0)"),true);
  assert.equal(run("$('#workflow-failure-reason').textContent"),'Another project failure');
  assert.equal(run("showWorkflowStepFailure('p','r',0)"),true);
  assert.equal(run("$('#workflow-failure-reason').textContent"),'Original NVD failure');
});

test('clicking a failure marker routes to that exact workflow step',async()=>{
  const run=fixture();
  await run(`document.listeners.click({target:{closest:selector=>selector==='[data-step-failure]'?{dataset:{projectId:'p',runId:'r',stepIndex:'2'}}:null}})`);
  assert.equal(run('opens'),1);
  assert.equal(run("$('#workflow-failure-step').textContent"),'NIST NVD · PHP 8.3');
  assert.equal(run("$('#workflow-failure-reason').textContent"),'Different component failure');
});
