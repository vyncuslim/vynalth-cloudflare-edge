/**
 * Repeatable offline acceptance; synthetic inputs only. This intentionally
 * reports the unblocked advisory attacks rather than excluding them.
 * No live target, sockets, credentials, external requests or generated attack traffic.
 */
import {performance} from "node:perf_hooks";
import {inspectWafRequest,CORE_HOSTS} from "../src/vynalth-waf-core.js";
import {inspectApiSchema} from "../src/vwaf-schema.js";
const cases=[],add=(name,host,path,malicious,expect,body)=>cases.push({name,host,path,malicious,expect,body});
const hard=["/.env","/.git/config","/.netrc","/.ssh/id_rsa","/terraform.tfstate","/privatekey.pem","/wp-login.php","/.vault-token","/debug/pprof/heap","/etc/passwd","/.config/gh/hosts.yml","/.docker/config.json"];
const observed=[["sql","/api/example?id=1%20union%20select%20fixture"],["xss","/api/example?id=%3Cscript%3Efixture%3C%2Fscript%3E"],["local-destination","/api/example?url=http%3A%2F%2Flocalhost"],["template","/api/example?id=%7B%7Bfixture%7D%7D"]];
for(const host of CORE_HOSTS){
 for(const path of hard)add("private-path",host,path,true,true);
 for(const [name,path] of observed)add(name,host,path,true,false);
 for(let n=0;n<320;n++){
  const paths=["/","/robots.txt","/sitemap.xml","/.well-known/security.txt","/en","/login","/docs/example.php.txt","/api/health","/openapi.json","/firebase.json","/env.js","/search?q=SQL%20tutorial","/search?q=%3Cscript%3E%20example","/docs/"+n,"/assets/app-"+n+".js","/api/example?page="+n];
  add("benign",host,paths[n%paths.length],false,false);
 }
}
for(const aspectRatio of ["bad","<script>fixture</script>","1 union select fixture"])add("invalid-enum","vynalthai.com","/api/ai/image",true,true,{prompt:"example",aspectRatio});
for(const text of ["<script> tutorial","SQL union select example","中文搜索","Hello 🌎"]){
 add("benign-free-text","vynalthai.com","/api/web-search",false,false,{query:text});
 add("benign-prompt","vynalthai.com","/api/ai/image",false,false,{prompt:text,aspectRatio:"1:1"});
}
let attack=0,blocked=0,benign=0,falsePositive=0,regression=0;const reqs=cases.map(c=>new Request("https://"+c.host+c.path,{method:c.body?"POST":"GET"}));
const evaluate=(c,r)=>inspectWafRequest(r).block||(c.body&&inspectApiSchema(c.path,c.body).some(s=>s.blocking))===true;
for(let i=0;i<cases.length;i++){
 const c=cases[i],decision=evaluate(c,reqs[i]);
 if(c.malicious){attack++;if(decision)blocked++}else{benign++;if(decision)falsePositive++}
 if(decision!==c.expect)regression++;
}
// Warmup then per-call synchronous CPU-ish wall time, excluding Request creation,
// IO, body streaming, remote actor checks, provider runtime and load contention.
for(let i=0;i<5000;i++)evaluate(cases[i%cases.length],reqs[i%reqs.length]);
const samples=[];for(let i=0;i<20000;i++){const n=i%cases.length,t=performance.now();evaluate(cases[n],reqs[n]);samples.push(performance.now()-t)}
samples.sort((a,b)=>a-b);const p95=samples[Math.ceil(samples.length*.95)-1];
const report={suite:"vwaf-v2-rc1-synthetic",runtime:process.version,attack:{tested:attack,blocked,rate:blocked/attack},benign:{tested:benign,falsePositive,rate:falsePositive/benign},performance:{samples:samples.length,p95Ms:p95},regressions:regression,
 goals:{knownAttackBlock:blocked/attack>=.99,benignFalsePositive:falsePositive/benign<.001,localP95:p95<5,productionAvailability:null,independentSecurityAudit:null},
 limitations:"Synthetic selected scenarios, not real traffic, not independent corpus, no distributed load or production SLA evidence."};
console.log("VWAF_ACCEPTANCE "+JSON.stringify(report));
if(regression||falsePositive)process.exitCode=1;
// Formal release intentionally refuses unverified production and audit gates.
if(process.argv.includes("--release")&&Object.values(report.goals).some(x=>x!==true))process.exitCode=2;
