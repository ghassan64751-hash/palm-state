const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000;
const ADMIN_USER=process.env.ADMIN_USER||'admminna',ADMIN_PASS=process.env.ADMIN_PASS||'admminna';
const DB=path.join(__dirname,'data.json');
let db={maintenance:{on:false,msg:'نعمل على تحسين الموقع وسنعود قريباً.'},notices:[]};
try{db={...db,...JSON.parse(fs.readFileSync(DB,'utf8'))}}catch{}
const save=()=>{try{fs.writeFileSync(DB,JSON.stringify(db))}catch{}};
const PAGE=fs.readFileSync(path.join(__dirname,'public','index.html'));
const hash=s=>crypto.createHash('sha256').update(String(s)).digest();
const same=(a,b)=>crypto.timingSafeEqual(hash(a),hash(b));
const tokens=new Map(),fails=new Map();
const send=(res,code,obj)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(obj))};
const body=req=>new Promise(r=>{let d='';req.on('data',c=>{d+=c;if(d.length>1e5)req.destroy()});req.on('end',()=>{try{r(JSON.parse(d||'{}'))}catch{r({})}})});
const authed=req=>{const t=(req.headers.authorization||'').replace('Bearer ','');const e=tokens.get(t);return !!e&&e>Date.now()};

http.createServer(async(req,res)=>{
 const u=req.url.split('?')[0];
 if(!u.startsWith('/api/')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(PAGE)}
 if(u==='/api/state'&&req.method==='GET')return send(res,200,{maintenance:db.maintenance,notices:db.notices});
 const b=req.method==='POST'?await body(req):{};

 if(u==='/api/login'&&req.method==='POST'){
  const ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();
  const f=fails.get(ip)||{n:0,t:0},fresh=Date.now()-f.t<6e5;
  if(fresh&&f.n>=5)return send(res,429,{error:'محاولات كثيرة، حاول بعد 10 دقائق'});
  if(same(b.user,ADMIN_USER)&&same(b.pass,ADMIN_PASS)){
   fails.delete(ip);
   const t=crypto.randomBytes(24).toString('hex');tokens.set(t,Date.now()+432e5);
   return send(res,200,{token:t});
  }
  fails.set(ip,{n:(fresh?f.n:0)+1,t:Date.now()});
  return send(res,401,{error:'اسم المستخدم أو كلمة السر غير صحيحة'});
 }

 if(!u.startsWith('/api/admin/'))return send(res,404,{error:'غير موجود'});
 if(!authed(req))return send(res,401,{error:'غير مصرح'});

 if(u==='/api/admin/maintenance'){
  db.maintenance={on:!!b.on,msg:String(b.msg||'').trim().slice(0,200)||db.maintenance.msg};
  save();return send(res,200,db);
 }
 if(u==='/api/admin/notice'){
  const text=String(b.text||'').trim().slice(0,300);
  if(!text)return send(res,400,{error:'اكتب نص الإشعار'});
  db.notices.unshift({id:crypto.randomBytes(4).toString('hex'),text,at:Date.now()});
  db.notices=db.notices.slice(0,20);save();return send(res,200,db);
 }
 if(u==='/api/admin/notice/delete'){
  db.notices=db.notices.filter(n=>n.id!==b.id);save();return send(res,200,db);
 }
 send(res,404,{error:'غير موجود'});
}).listen(PORT,()=>console.log('listening on '+PORT));
