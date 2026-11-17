const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'xxc.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS apps (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL, version TEXT NOT NULL, category TEXT NOT NULL,
 description TEXT NOT NULL, filename TEXT NOT NULL, original_name TEXT NOT NULL,
 size INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL);
`);
if (!db.prepare('SELECT id FROM admin WHERE id=1').get()) {
  if (!process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 12) {
    console.error('Set ADMIN_PASSWORD to a strong password (at least 12 characters).');
    process.exit(1);
  }
  db.prepare('INSERT INTO admin(id,password_hash) VALUES(1,?)').run(bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12));
}
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('Set SESSION_SECRET to a random secret of at least 32 characters.');
  process.exit(1);
}
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(session({
  name: 'xxc.sid',
  secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 8*60*60*1000 }
}));
app.use('/uploads', express.static(UPLOAD_DIR, { fallthrough: false, setHeaders: res => res.setHeader('X-Content-Type-Options','nosniff') }));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
 destination: (req,file,cb)=>cb(null,UPLOAD_DIR),
 filename: (req,file,cb)=>cb(null,crypto.randomUUID()+'.apk')
});
const upload = multer({
 storage, limits:{fileSize:200*1024*1024, files:1},
 fileFilter:(req,file,cb)=>{
   const ext = path.extname(file.originalname).toLowerCase();
   if (ext !== '.apk' || (file.mimetype !== 'application/vnd.android.package-archive' && file.mimetype !== 'application/octet-stream')) return cb(new Error('ارفع ملف APK فقط'));
   cb(null,true);
 }
});
const requireAdmin=(req,res,next)=>req.session.admin ? next() : res.status(401).json({error:'يجب تسجيل الدخول'});
const valid=(s,max)=>typeof s==='string' && s.trim().length>0 && s.trim().length<=max;

app.get('/api/apps',(req,res)=>{
 const rows=db.prepare('SELECT id,name,version,category,description,filename,size,created_at FROM apps ORDER BY id DESC').all();
 res.json(rows.map(x=>({...x, downloadUrl:'/uploads/'+encodeURIComponent(x.filename)})));
});
app.post('/api/login',(req,res)=>{
 const row=db.prepare('SELECT password_hash FROM admin WHERE id=1').get();
 if(!valid(req.body.password,200) || !bcrypt.compareSync(req.body.password,row.password_hash)) return res.status(401).json({error:'كلمة المرور غير صحيحة'});
 req.session.regenerate(err=>{ if(err)return res.status(500).json({error:'تعذر بدء الجلسة'}); req.session.admin=true; res.json({ok:true}); });
});
app.post('/api/logout',requireAdmin,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/session',(req,res)=>res.json({authenticated:!!req.session.admin}));
app.post('/api/apps',requireAdmin,(req,res)=>{
 upload.single('apk')(req,res,err=>{
   if(err) return res.status(400).json({error:err.message || 'فشل رفع الملف'});
   const {name,version,category,description}=req.body;
   if(!valid(name,70)||!valid(version,30)||!valid(category,30)||!valid(description,500)){
     if(req.file)fs.unlink(req.file.path,()=>{});
     return res.status(400).json({error:'تأكد من ملء كل الحقول ضمن الحدود المطلوبة'});
   }
   if(!req.file)return res.status(400).json({error:'اختر ملف APK'});
   const info=db.prepare('INSERT INTO apps(name,version,category,description,filename,original_name,size) VALUES(?,?,?,?,?,?,?)')
    .run(name.trim(),version.trim(),category.trim(),description.trim(),req.file.filename,path.basename(req.file.originalname),req.file.size);
   res.json({ok:true,id:info.lastInsertRowid});
 });
});
app.delete('/api/apps/:id',requireAdmin,(req,res)=>{
 const row=db.prepare('SELECT filename FROM apps WHERE id=?').get(Number(req.params.id));
 if(!row)return res.status(404).json({error:'التطبيق غير موجود'});
 db.prepare('DELETE FROM apps WHERE id=?').run(Number(req.params.id));
 fs.unlink(path.join(UPLOAD_DIR,row.filename),()=>{});
 res.json({ok:true});
});
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.use((err,req,res,next)=>{ console.error(err); res.status(500).json({error:'حدث خطأ في الخادم'}); });
app.listen(PORT,()=>console.log(`XXC running on port ${PORT}`));
