
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.set("trust proxy", 1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"20kb"}));
app.use(cors({
 origin:process.env.ADMIN_ORIGIN,
 methods:["GET","POST"],
 allowedHeaders:["Content-Type","Authorization"]
}));

const db = new Pool({
 connectionString:process.env.DATABASE_URL,
 ssl:{rejectUnauthorized:false}
});

const JWT_SECRET=process.env.JWT_SECRET;
const RENDER_KEY=process.env.RENDER_API_KEY;
const SERVICE_ID=process.env.TARGET_SERVICE_ID;

if(!JWT_SECRET || JWT_SECRET.length<32 || !process.env.DATABASE_URL){
 throw Error("DATABASE_URL و JWT_SECRET مطلوبان");
}

const limiter=rateLimit({
 windowMs:15*60*1000,
 limit:8
});

async function init(){
 await db.query(`
 CREATE TABLE IF NOT EXISTS admin_account(
 id integer PRIMARY KEY,
 username text NOT NULL,
 password_hash text NOT NULL,
 version integer DEFAULT 1
 );
 CREATE TABLE IF NOT EXISTS admin_settings(
 key text PRIMARY KEY,value text NOT NULL
 );
 CREATE TABLE IF NOT EXISTS admin_logs(
 id bigserial PRIMARY KEY,
 action text,result text,
 created_at timestamptz DEFAULT now()
 );
 CREATE TABLE IF NOT EXISTS page_views(
 id bigserial PRIMARY KEY,
 created_at timestamptz DEFAULT now(),
 device text,browser text,source text
 );
 `);

 const found=await db.query("SELECT id FROM admin_account WHERE id=1");
 if(!found.rowCount){
  const password=process.env.ADMIN_PASS||"1234";
  const username=process.env.ADMIN_USER||"1234";
  const hash=await bcrypt.hash(password,12);
  await db.query(
   "INSERT INTO admin_account(id,username,password_hash) VALUES(1,$1,$2)",
   [username,hash]
  );
 }
 await db.query(
  "INSERT INTO admin_settings(key,value) VALUES('maintenance','false') ON CONFLICT DO NOTHING"
 );
}

async function auth(req,res,next){
 try{
  const raw=(req.headers.authorization||"").replace("Bearer ","");
  const p=jwt.verify(raw,JWT_SECRET);
  const q=await db.query("SELECT version FROM admin_account WHERE id=1");
  if(!q.rowCount||q.rows[0].version!==p.version)throw Error();
  next();
 }catch{
  res.status(401).json({error:"انتهت الجلسة، سجل الدخول مجددًا"});
 }
}

async function log(action,result){
 await db.query(
  "INSERT INTO admin_logs(action,result) VALUES($1,$2)",
  [action,result]
 );
}

app.get("/health",async(req,res)=>{
 try{await db.query("SELECT 1");res.json({ok:true})}
 catch{res.status(503).json({ok:false})}
});

app.post("/api/login",limiter,async(req,res)=>{
 try{
  const q=await db.query("SELECT * FROM admin_account WHERE id=1");
  const a=q.rows[0];
  if(!a||a.username!==req.body.username||
    !(await bcrypt.compare(String(req.body.password||""),a.password_hash))){
   await log("تسجيل الدخول","مرفوض");
   return res.status(401).json({error:"بيانات الدخول غير صحيحة"});
  }
  await log("تسجيل الدخول","ناجح");
  res.json({
   token:jwt.sign({version:a.version},JWT_SECRET,{expiresIn:"8h"}),
   mustChangePassword:a.password_hash===await bcrypt.hash("never-match",12)
  });
 }catch{
  res.status(500).json({error:"خطأ داخلي"});
 }
});

app.post("/api/credentials",auth,limiter,async(req,res)=>{
 try{
  const {username,oldPassword,newPassword}=req.body;
  if(!/^[\w.-]{3,32}$/.test(username||"")||!newPassword||newPassword.length<12)
   return res.status(400).json({error:"اسم المستخدم غير صالح أو كلمة المرور قصيرة"});
  const q=await db.query("SELECT * FROM admin_account WHERE id=1");
  if(!(await bcrypt.compare(oldPassword||"",q.rows[0].password_hash)))
   return res.status(401).json({error:"كلمة المرور الحالية غير صحيحة"});
  const hash=await bcrypt.hash(newPassword,12);
  const u=await db.query(
   "UPDATE admin_account SET username=$1,password_hash=$2,version=version+1 WHERE id=1 RETURNING version",
   [username,hash]
  );
  await log("تغيير بيانات الدخول","ناجح");
  res.json({
   token:jwt.sign({version:u.rows[0].version},JWT_SECRET,{expiresIn:"8h"}),
   message:"تم تغيير بيانات الدخول"
  });
 }catch{res.status(500).json({error:"تعذر تحديث الحساب"})}
});

app.post("/api/track",async(req,res)=>{
 try{
  const ua=req.headers["user-agent"]||"";
  const device=/Android|iPhone|Mobile|iPad/i.test(ua)?"جوال":"كمبيوتر";
  const browser=/Edg\//.test(ua)?"Edge":
   /Firefox\//.test(ua)?"Firefox":
   /Chrome\//.test(ua)?"Chrome":
   /Safari\//.test(ua)?"Safari":"غير معروف";
  let source="مباشر";
  try{if(req.body.referrer)source=new URL(req.body.referrer).hostname}catch{}
  await db.query(
   "INSERT INTO page_views(device,browser,source) VALUES($1,$2,$3)",
   [device,browser,source]
  );
 }catch{}
 res.status(204).end();
});

app.get("/api/overview",auth,async(req,res)=>{
 try{
  const [today,month,active,visits,setting]=await Promise.all([
   db.query("SELECT count(*)::int n FROM page_views WHERE created_at>=date_trunc('day',now())"),
   db.query("SELECT count(*)::int n FROM page_views WHERE created_at>=now()-interval '30 days'"),
   db.query("SELECT count(*)::int n FROM page_views WHERE created_at>=now()-interval '5 minutes'"),
   db.query("SELECT * FROM page_views ORDER BY created_at DESC LIMIT 30"),
   db.query("SELECT value FROM admin_settings WHERE key='maintenance'")
  ]);
  res.json({
   today:today.rows[0].n,
   month:month.rows[0].n,
   active:active.rows[0].n,
   visits:visits.rows,
   tracking:month.rows[0].n>0,
   maintenance:setting.rows[0]?.value==="true",
   serverTime:new Date().toISOString()
  });
 }catch{res.status(500).json({error:"تعذر تحميل الإحصائيات"})}
});

app.post("/api/maintenance",auth,async(req,res)=>{
 const enabled=!!req.body.enabled;
 await db.query(
  "UPDATE admin_settings SET value=$1 WHERE key='maintenance'",
  [String(enabled)]
 );
 await log("وضع الصيانة",enabled?"تفعيل":"إلغاء");
 res.json({message:"تم حفظ حالة الصيانة في الخادم"});
});

app.get("/api/logs",auth,async(req,res)=>{
 const q=await db.query(
  "SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT 100"
 );
 res.json({logs:q.rows});
});

app.post("/api/site/:action",auth,async(req,res)=>{
 const action=req.params.action;
 if(!["suspend","resume"].includes(action))
  return res.status(400).json({error:"عملية غير معروفة"});
 if(!RENDER_KEY||!SERVICE_ID)
  return res.status(503).json({error:"لم يتم إعداد بيانات Render في الخادم"});
 try{
  const r=await fetch(
   `https://api.render.com/v1/services/${SERVICE_ID}/${action}`,
   {method:"POST",headers:{
    Authorization:"Bearer "+RENDER_KEY,
    Accept:"application/json"
   }}
  );
  if(!r.ok)throw Error("Render API "+r.status);
  await log(action==="suspend"?"إيقاف الموقع":"تشغيل الموقع","تم إرسال الطلب");
  res.json({message:"تم إرسال الأمر إلى Render"});
 }catch(e){
  res.status(503).json({error:e.message});
 }
});

app.listen(process.env.PORT||10000,"0.0.0.0",()=>{
 console.log("BASAM ADMIN API STARTED");
 init().catch(e=>{console.error(e);process.exit(1)});
});
