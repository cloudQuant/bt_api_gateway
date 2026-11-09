// Synthetic HTTP fixture only; verifies frontend sequencing and persisted receipts.
const http = require('http'), fs = require('fs'), path = require('path')
const { chromium } = require(process.env.PLAYWRIGHT_PATH || 'playwright')
const root = path.resolve(__dirname, '../../src/bt_api_gateway/web/static')
const prepares = [], runs = [], commands = new Map(); let uncertain = false, inactive = false
const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost')
  if (u.pathname.endsWith('/session')) return json(res, {csrf_token:'c'.repeat(32), namespace:'synthetic', receipt_key_persistent:true, scopes:[{scope_id:'desk',strategy_ref:'strategy',route_fingerprint:'a'.repeat(64)}]})
  if (u.pathname.endsWith('/snapshot')) return json(res, {status:'UNAVAILABLE'})
  if (u.pathname.endsWith('/causes') && req.method === 'GET') return json(res, {status:'OBSERVED',scope_receipt:'scope-view',causes:[{cause_id:'existing',mode:'STOP_NEW',active:1,version:4,view_receipt:'cause-view'}]})
  if (req.method === 'POST') {
    let b = ''; req.on('data', c => b += c); return req.on('end', () => {
      const data=JSON.parse(b)
      if (u.pathname.endsWith('/prepare')) { prepares.push(data); const receipt='synthetic-'+data.request_id; commands.set(receipt,data); return json(res,{status:'PREPARED',receipt}) }
      if (u.pathname.endsWith('/status')) { const command=commands.get(data.receipt); return json(res,uncertain?{status:'UNKNOWN'}:inactive&&command.mode==='STOP_NEW'?{status:'OBSERVED',cause:{cause_id:command.request_id,active:0}}:command.mode==='RESUME'?{status:'NOT_FOUND',operation_id:command.request_id}:{status:'NOT_FOUND',cause_id:command.request_id}) }
      if (u.pathname.endsWith('/run')) { runs.push(data); return json(res,{status:runs.filter(x=>x.receipt===data.receipt).length===1?'UNKNOWN':'OBSERVED'}) }
      return json(res,{status:'UNKNOWN'})
    })
  }
  const target=u.pathname==='/'?path.join(root,'index.html'):path.resolve(root,'.'+u.pathname)
  if (!target.startsWith(root+'/')) {res.writeHead(403);return res.end()}
  fs.readFile(target,(err,data)=>{if(err){res.writeHead(404);return res.end()}res.writeHead(200,{'Content-Type':target.endsWith('.js')?'text/javascript':target.endsWith('.css')?'text/css':'text/html'});res.end(data)})
})
function json(res,value){res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(value))}
;(async()=>{
  await new Promise(r=>server.listen(0,'127.0.0.1',r))
  const browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_PATH})
  try {
    const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message))
    await page.goto(`http://127.0.0.1:${server.address().port}/`,{waitUntil:'networkidle'})
    async function action(name){await page.getByRole('button',{name,exact:true}).click();await page.getByRole('button',{name:'继续',exact:true}).click();await page.waitForTimeout(100)}
    async function retry(){await page.getByRole('button',{name:'重试原请求',exact:true}).click();await page.getByRole('dialog').getByRole('button',{name:'重试原请求',exact:true}).click();await page.waitForTimeout(100)}
    await action('停止新单');await action('停止新单');if(prepares.length!==1||runs.length!==1)throw Error('automatic resubmission');await retry()
    if(runs.length!==2||runs[0].receipt!==runs[1].receipt)throw Error('original apply receipt not reused')
    inactive=true;await action('停止新单');await page.getByRole('button',{name:'允许新的独立控制请求'}).click();await page.getByRole('button',{name:'允许',exact:true}).click();await action('停止新单')
    if(prepares.length!==2||prepares[0].request_id===prepares[1].request_id)throw Error('new independent request did not obtain new ID')
    await action('解除');await action('解除');if(prepares.length!==3||runs.length!==4)throw Error('automatic resume');await retry()
    if(runs.length!==5||runs[3].receipt!==runs[4].receipt||prepares[2].expected_version!==4)throw Error('original resume receipt or version changed')
    uncertain=true;await action('冻结');await action('冻结');if(await page.getByRole('button',{name:'重试原请求',exact:true}).count())throw Error('UNKNOWN allowed retry')
    await page.getByText('结果待人工核查',{exact:false}).waitFor();if(errors.length)throw Error(errors.join(','))
    console.log('synthetic browser: original signed receipts reused only after confirmed NOT_FOUND; UNKNOWN stays manual')
  } finally {await browser.close();server.close()}
})().catch(error=>{console.error(error);server.close();process.exitCode=1})
