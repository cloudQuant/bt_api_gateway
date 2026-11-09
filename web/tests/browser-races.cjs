const http=require('http'),fs=require('fs'),path=require('path')
const {chromium}=require(process.env.PLAYWRIGHT_PATH || 'playwright')
const root=path.resolve(__dirname, '../../src/bt_api_gateway/web/static')
let posts=0,snapshotCalls=0
function json(res,v){res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(v))}
const server=http.createServer((req,res)=>{const u=new URL(req.url,'http://localhost'),scope=u.pathname.includes('/scopes/A/')?'A':'B'
 if(req.method==='POST' && u.pathname.endsWith('/targets/query')){let body='';req.on('data',c=>body+=c);return req.on('end',()=>{const c=JSON.parse(body).view_receipt.replace('view-','');setTimeout(()=>json(res,{status:'OBSERVED',targets:[{reservation_id:'target-'+c,operation_id:'operation-'+c,view_receipt:'target-view-'+c,state:'PENDING'}]}),c==='B1'?800:20)})}
 if(req.method==='POST' && u.pathname.endsWith('/requests/prepare'))return json(res,{status:'PREPARED',receipt:'synthetic-only'})
 if(req.method==='POST' && u.pathname.endsWith('/requests/status'))return json(res,{status:'UNKNOWN'})
 if(req.method==='POST'){posts++;return json(res,{status:'UNKNOWN'})}
 if(u.pathname.endsWith('/session'))return json(res,{csrf_token:'c'.repeat(32),namespace:'synthetic',scopes:['A','B'].map(s=>({scope_id:s,strategy_ref:s,route_fingerprint:s==='A'?'a'.repeat(64):'b'.repeat(64)}))})
 if(u.pathname.endsWith('/snapshot')){snapshotCalls++;return setTimeout(()=>json(res,{status:'OBSERVED',version:scope}),scope==='A'?1000:20)}
 if(u.pathname.endsWith('/causes'))return setTimeout(()=>json(res,{status:'OBSERVED',scope_receipt:'scope-'+scope,causes:(scope==='A'?['A1']:['B1','B2']).map(cause_id=>({cause_id,mode:'DRAIN',version:1,active:1,view_receipt:'view-'+cause_id}))}),scope==='A'?1000:20)
 const target=u.pathname==='/'?path.join(root,'index.html'):path.resolve(root,'.'+u.pathname);if(!target.startsWith(root+'/')){res.writeHead(403);return res.end()};fs.readFile(target,(e,b)=>{if(e){res.writeHead(404);return res.end()}res.writeHead(200,{'Content-Type':target.endsWith('.js')?'text/javascript':target.endsWith('.css')?'text/css':'text/html'});res.end(b)})})
;(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_PATH});try{
 const page=await browser.newPage();const errs=[];page.on('pageerror',e=>errs.push(e.message));await page.goto(`http://127.0.0.1:${server.address().port}/`,{waitUntil:'domcontentloaded'});await page.getByText('策略视图 / A').waitFor();await page.locator('.el-select').click();await page.getByRole('option',{name:'策略 · B'}).click();await page.getByText('B1 · v1').waitFor();await page.waitForTimeout(1200)
 if(await page.getByText('A1 · v1').count())throw Error('scope A stale response overwrote B');if(!(await page.getByText('B2 · v1').count()))throw Error('scope B missing');if(snapshotCalls!==0||!(await page.getByText('SOURCE_PROVENANCE_UNAVAILABLE',{exact:false}).count()))throw Error('unverified snapshot displayed')
 const selectCause=async id=>page.locator('.cause').filter({hasText:id+' · v1'}).getByRole('button',{name:'查看撤单目标'}).click()
 await selectCause('B1');await selectCause('B2');await page.getByText('target-B2').waitFor();await page.waitForTimeout(1000)
 if(await page.getByText('target-B1').count())throw Error('older B1 target overwrote B2');if(!(await page.getByText('target-B2').count()))throw Error('B2 target missing')
 await page.getByRole('button',{name:'执行',exact:true}).click();await page.getByRole('button',{name:'取消',exact:true}).click();if(posts)throw Error('unexpected write'); for(let i=0;i<2;i++){await page.getByRole('button',{name:'停止新单'}).click();await page.getByRole('button',{name:'继续',exact:true}).click();await page.waitForTimeout(100)};if(posts!==1)throw Error('duplicate post without journal evidence');await page.getByText('结果待人工核查',{exact:false}).waitFor();if(await page.getByRole('button',{name:'重试原请求'}).count())throw Error('unsafe retry visible')
 if(errs.length)throw Error(errs.join(','));console.log('synthetic browser: delayed A->B reads ignored; older B1 target ignored after B2; no stale target action')
 }finally{await browser.close();server.close()}})().catch(e=>{console.error(e);server.close();process.exitCode=1})
