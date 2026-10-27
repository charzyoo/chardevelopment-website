// Char Development website API + private admin dashboard. No dependencies (Node 18+).
'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const DATA=process.env.CHARDEV_DATA||'/opt/chardev/data';
const PORT=+process.env.CHARDEV_PORT||7171;
const CFG=path.join(DATA,'admin.json');           // {salt, hash}
const F={ideas:path.join(DATA,'ideas.json'),reviews:path.join(DATA,'reviews.json'),stats:path.join(DATA,'stats.json')};
fs.mkdirSync(DATA,{recursive:true});
function load(f){try{return JSON.parse(fs.readFileSync(f,'utf8'))}catch(e){return[]}}
function save(f,v){const t=f+'.tmp';fs.writeFileSync(t,JSON.stringify(v,null,1));fs.renameSync(t,f)}

// ---- Visitor stats (no IPs stored: visitors are counted with a hash that changes every day) ----
let ST=(()=>{try{return JSON.parse(fs.readFileSync(F.stats,'utf8'))}catch(e){return{days:{}}}})();
let uniq={day:'',salt:'',set:new Set()};
function today(){return new Date(Date.now()+3*3600e3).toISOString().slice(0,10)} // Bahrain day
function dayObj(d){return ST.days[d]||(ST.days[d]={u:0,v:0,pages:{},designs:{},cats:{},wa:0,waFrom:{},forms:0,reviews:0,refs:{},dev:{},lang:{}})}
function inc(o,k,n){k=String(k||'').slice(0,80);if(!k)return;if(Object.keys(o).length>400&&!(k in o))return;o[k]=(o[k]||0)+(n||1)}
let dirty=false;setInterval(()=>{if(!dirty)return;dirty=false;const ks=Object.keys(ST.days).sort();while(ks.length>400)delete ST.days[ks.shift()];save(F.stats,ST)},15e3).unref();
process.on('SIGTERM',()=>{try{if(dirty)save(F.stats,ST)}catch(e){}process.exit(0)});
function seen(req,d){if(uniq.day!==d)uniq={day:d,salt:crypto.randomBytes(16).toString('hex'),set:new Set()};
 const h=crypto.createHash('sha256').update(uniq.salt+ipOf(req)+(req.headers['user-agent']||'')).digest('hex').slice(0,16);
 if(uniq.set.has(h))return false;uniq.set.add(h);return true}
function refHost(r){try{const h=new URL(r).hostname.replace(/^www\./,'');return /chardevelopment\.site$/.test(h)?'':h}catch(e){return ''}}
function track(req,e){const d=today(),o=dayObj(d),t=String(e.t||'');
 if(t==='view'){o.v++;if(seen(req,d)){o.u++;inc(o.dev,/Mobi|Android|iPhone/i.test(req.headers['user-agent']||'')?'mobile':'desktop');inc(o.lang,e.l==='en'?'en':'ar');
   const src=String(e.s||'').toLowerCase().slice(0,40)||refHost(e.r)||'direct';inc(o.refs,src)}inc(o.pages,e.p||'home')}
 else if(t==='page')inc(o.pages,e.p)
 else if(t==='design'){inc(o.designs,e.p);inc(o.cats,String(e.p||'').split('-')[0])}
 else if(t==='wa'){o.wa++;inc(o.waFrom,e.p||'other')}
 else return;dirty=true}
const sessions=new Map(); // token -> expiry
const hits=new Map();     // ip -> [timestamps]
function limited(ip,max,win){const now=Date.now();const a=(hits.get(ip)||[]).filter(t=>now-t<win);a.push(now);hits.set(ip,a);return a.length>max}
setInterval(()=>{const now=Date.now();for(const[k,v]of hits)if(!v.some(t=>now-t<3600e3))hits.delete(k);for(const[k,v]of sessions)if(v<now)sessions.delete(k)},600e3).unref();
function body(req,max=20000){return new Promise((ok,no)=>{let b='';req.on('data',c=>{b+=c;if(b.length>max){no(new Error('big'));req.destroy()}});req.on('end',()=>ok(b));req.on('error',no)})}
function parse(req,b){const t=(req.headers['content-type']||'');if(t.includes('json')){try{return JSON.parse(b)}catch(e){return{}}}const p=new URLSearchParams(b),o={};for(const[k,v]of p){if(k in o){o[k]=[].concat(o[k],v)}else o[k]=v}return o}
function clip(v,n){return String(Array.isArray(v)?v.join(', '):(v??'')).trim().slice(0,n)}
function send(res,code,obj,h={}){res.writeHead(code,Object.assign({'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'},h));res.end(JSON.stringify(obj))}
function ipOf(req){return (req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim()}
function cookie(req,n){const m=(req.headers.cookie||'').match(new RegExp('(?:^|; )'+n+'=([^;]+)'));return m?m[1]:null}
function authed(req){const t=cookie(req,'cd_admin');return t&&sessions.has(t)&&sessions.get(t)>Date.now()}
function checkPw(pw,user){let c;try{c=JSON.parse(fs.readFileSync(CFG,'utf8'))}catch(e){return false}if(c.user&&String(user||'').trim().toLowerCase()!==c.user)return false;const h=crypto.scryptSync(String(pw),Buffer.from(c.salt,'hex'),64);const s=Buffer.from(c.hash,'hex');return s.length===h.length&&crypto.timingSafeEqual(s,h)}
const ADMIN_HTML=fs.readFileSync(path.join(__dirname,'admin.html'));
http.createServer(async(req,res)=>{
 const u=new URL(req.url,'http://x');const ip=ipOf(req);
 try{
  if(req.method==='GET'&&(u.pathname==='/admin'||u.pathname==='/admin/')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Frame-Options':'DENY','X-Robots-Tag':'noindex'});return res.end(ADMIN_HTML)}
  if(req.method==='POST'&&u.pathname==='/api/hit'){if(limited('H'+ip,400,3600e3))return send(res,204,{});let e={};try{e=JSON.parse(await body(req,2000))}catch(x){}track(req,e);res.writeHead(204);return res.end()}
  if(req.method==='GET'&&u.pathname==='/api/reviews'){return send(res,200,load(F.reviews).filter(r=>r.status==='approved').map(r=>({stars:r.stars,text:r.text,name:r.name,biz:r.biz})),{'Cache-Control':'public, max-age=60'})}
  if(req.method==='POST'&&(u.pathname==='/api/idea'||u.pathname==='/api/review')){
   if(limited(ip,8,3600e3))return send(res,429,{ok:false});
   const d=parse(req,await body(req));if(d['bot-field'])return send(res,200,{ok:true});
   const id=crypto.randomBytes(6).toString('hex'),at=new Date().toISOString();
   if(u.pathname==='/api/idea'){const r={id,at,name:clip(d.name,120),phone:clip(d.phone,40),business:clip(d.business,160),email:clip(d.email,160),service:clip(d.service,300),idea:clip(d.idea,4000),done:false};
    if(!r.name||!r.phone||!r.idea)return send(res,400,{ok:false});const a=load(F.ideas);a.unshift(r);save(F.ideas,a.slice(0,5000));dayObj(today()).forms++;dirty=true;return send(res,200,{ok:true})}
   const st=Math.max(1,Math.min(5,parseInt(d.rating,10)||5));const r={id,at,stars:st,name:clip(d.name,80),biz:clip(d.business,120),text:clip(d.review,1500),phone:clip(d.phone,40),status:'pending'};
   if(!r.name||r.text.length<5)return send(res,400,{ok:false});const a=load(F.reviews);a.unshift(r);save(F.reviews,a.slice(0,5000));dayObj(today()).reviews++;dirty=true;return send(res,200,{ok:true})}
  if(req.method==='POST'&&u.pathname==='/api/admin/login'){
   if(limited('L'+ip,10,900e3))return send(res,429,{ok:false,msg:'Too many tries. Wait 15 minutes.'});
   const d=parse(req,await body(req,2000));if(!checkPw(d.password,d.user))return send(res,401,{ok:false});
   const t=crypto.randomBytes(32).toString('hex');sessions.set(t,Date.now()+7*864e5);
   return send(res,200,{ok:true},{'Set-Cookie':`cd_admin=${t}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`})}
  if(u.pathname.startsWith('/api/admin/')){
   if(!authed(req))return send(res,401,{ok:false});
   if(req.method==='GET'&&u.pathname==='/api/admin/data')return send(res,200,{ideas:load(F.ideas),reviews:load(F.reviews),stats:ST.days,today:today()});
   if(req.method==='POST'&&u.pathname==='/api/admin/logout'){sessions.delete(cookie(req,'cd_admin'));return send(res,200,{ok:true},{'Set-Cookie':'cd_admin=; Path=/; Max-Age=0'})}
   if(req.method==='POST'&&u.pathname==='/api/admin/action'){
    const d=parse(req,await body(req,2000));const kind=d.kind==='idea'?'ideas':'reviews';const a=load(F[kind]);const i=a.findIndex(x=>x.id===d.id);if(i<0)return send(res,404,{ok:false});
    if(d.op==='delete')a.splice(i,1);else if(kind==='reviews'&&(d.op==='approve'||d.op==='hide'))a[i].status=d.op==='approve'?'approved':'pending';else if(kind==='ideas'&&d.op==='done')a[i].done=!a[i].done;else return send(res,400,{ok:false});
    save(F[kind],a);return send(res,200,{ok:true})}
  }
  send(res,404,{ok:false});
 }catch(e){send(res,400,{ok:false})}
}).listen(PORT,'127.0.0.1',()=>console.log('chardev api on',PORT));
