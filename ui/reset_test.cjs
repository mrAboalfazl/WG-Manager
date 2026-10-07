const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(process.argv[2] || __dirname + '/index.html', 'utf8');
const source = html.slice(html.indexOf('function openRecharge('), html.indexOf('function openRenew('));
const requests = [];
const context = vm.createContext({
  modal() {}, esc: x => x, enc: x => x,
  $: () => ({ value: '50', classList: { toggle() {} } }),
  document: { querySelectorAll: () => [] },
  api: async (method, path, body) => { requests.push({ method, path, body: JSON.parse(JSON.stringify(body)) }); },
  toast() {}, closeModal() {}, refresh() {}, encodeURIComponent,
});
vm.runInContext(source, context);
(async () => {
  for (const mode of ['set', 'add']) {
    vm.runInContext(`openRecharge('alice');segPick({dataset:{m:'${mode}'},classList:{add(){}}});`, context);
    await vm.runInContext("doRecharge('alice')", context);
    assert.deepEqual(requests.pop().body, { [mode + '_gb']: 50 });
    vm.runInContext("openRecharge('bob')", context);
    await vm.runInContext("doRecharge('bob')", context);
    assert.deepEqual(requests.pop(), { method:'POST', path:'/peers/bob/recharge', body:{reset:true} });
  }
  console.log('PASS: reopening Data after Set quota or Add data submits reset:true');
})().catch(err => { console.error(err); process.exitCode = 1; });
