const express=require("express"),fs=require("fs"),path=require("path"),crypto=require("crypto"),multer=require("multer"),cookieParser=require("cookie-parser"),Razorpay=require("razorpay");
const app=express(),PORT=process.env.PORT||3000,BASE=__dirname,STORE=path.join(BASE,"storage"),UP=path.join(STORE,"uploads"),DB=path.join(STORE,"db.json");
fs.mkdirSync(UP,{recursive:true});
if(!fs.existsSync(DB))fs.writeFileSync(DB,JSON.stringify({users:[],requests:[],sessions:[],payments:[],webhookEvents:[]},null,2));

/* Razorpay webhook must receive the raw request body for signature verification. */
app.post("/api/payments/webhook",express.raw({type:"application/json"}),(req,res)=>{
  try{
    const sig=req.headers["x-razorpay-signature"],secret=process.env.RAZORPAY_WEBHOOK_SECRET;
    if(!secret||!sig)return res.status(400).send("Webhook not configured");
    const expected=crypto.createHmac("sha256",secret).update(req.body).digest("hex");
    if(!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(sig)))return res.status(400).send("Invalid signature");
    const eventId=req.headers["x-razorpay-event-id"],d=db();
    if(eventId&&d.webhookEvents.includes(eventId))return res.status(200).send("ok");
    const payload=JSON.parse(req.body.toString("utf8"));
    if(eventId)d.webhookEvents.push(eventId);
    if(payload.event==="order.paid"){
      const order=payload.payload?.order?.entity;
      const payment=payload.payload?.payment?.entity;
      const r=d.requests.find(x=>x.razorpayOrderId===order?.id);
      if(r){r.paymentStatus="Paid";r.paymentId=payment?.id||r.paymentId;r.status=r.status==="New"?"Under Review":r.status}
    }
    save(d);return res.status(200).send("ok");
  }catch(e){console.error(e);return res.status(400).send("Webhook error")}
});

app.use(express.json({limit:"2mb"}));app.use(express.urlencoded({extended:true}));app.use(cookieParser());app.use(express.static(path.join(BASE,"public")));

function db(){return JSON.parse(fs.readFileSync(DB,"utf8"))}
function save(x){fs.writeFileSync(DB,JSON.stringify(x,null,2))}
function makeId(p){return p+"-"+new Date().getFullYear()+"-"+crypto.randomBytes(4).toString("hex").toUpperCase()}
function hash(p,s=crypto.randomBytes(16).toString("hex")){return {salt:s,hash:crypto.scryptSync(p,s,64).toString("hex")}}
function verify(p,u){const a=Buffer.from(hash(p,u.salt).hash,"hex"),b=Buffer.from(u.passwordHash,"hex");return a.length===b.length&&crypto.timingSafeEqual(a,b)}
function issueSession(uid,role){const token=crypto.randomBytes(32).toString("hex"),d=db();d.sessions=d.sessions.filter(s=>s.expires>Date.now());d.sessions.push({token,userId:uid,role,expires:Date.now()+7*86400000});save(d);return token}
function auth(req,res,next){const t=req.cookies.ca_session,d=db(),s=d.sessions.find(x=>x.token===t&&x.expires>Date.now());if(!s)return res.status(401).json({error:"Please log in."});req.user=d.users.find(u=>u.id===s.userId);if(!req.user)return res.status(401).json({error:"Account not found."});req.role=s.role;next()}
function owner(req,res,next){auth(req,res,()=>req.role==="owner"?next():res.status(403).json({error:"Owner access required."}))}
const allowedExt=new Set([".pdf",".jpg",".jpeg",".png",".doc",".docx"]);
const upload=multer({dest:UP,limits:{fileSize:10*1024*1024,files:5},fileFilter:(req,file,cb)=>allowedExt.has(path.extname(file.originalname).toLowerCase())?cb(null,true):cb(new Error("Unsupported file type"))});

const pricing={"RTI Application":299,"First Appeal":799,"Civic Complaint":999,"Government Representation":499,"Document Research":499,"Government Reply Analysis":499};

app.post("/api/signup",(req,res)=>{
 const {name,email,password,phone}=req.body;if(!name||!email||!password||password.length<8)return res.status(400).json({error:"Name, email and password of at least 8 characters are required."});
 const d=db();if(d.users.some(u=>u.email===email.toLowerCase()))return res.status(409).json({error:"Account already exists."});
 const h=hash(password),u={id:makeId("USR"),name,email:email.toLowerCase(),phone:phone||"",passwordHash:h.hash,salt:h.salt,role:"customer",createdAt:new Date().toISOString()};d.users.push(u);save(d);
 res.cookie("ca_session",issueSession(u.id,u.role),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:604800000});res.json({ok:true,user:{id:u.id,name:u.name,email:u.email}});
});
app.post("/api/login",(req,res)=>{
 const d=db(),u=d.users.find(x=>x.email===String(req.body.email||"").toLowerCase());if(!u||!verify(req.body.password||"",u))return res.status(401).json({error:"Invalid email or password."});
 res.cookie("ca_session",issueSession(u.id,u.role),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:604800000});res.json({ok:true,role:u.role,user:{id:u.id,name:u.name,email:u.email,phone:u.phone}});
});
app.post("/api/logout",auth,(req,res)=>{const d=db();d.sessions=d.sessions.filter(x=>x.token!==req.cookies.ca_session);save(d);res.clearCookie("ca_session");res.json({ok:true})});
app.get("/api/me",auth,(req,res)=>res.json({role:req.role,user:{id:req.user.id,name:req.user.name,email:req.user.email,phone:req.user.phone}}));

app.post("/api/requests",auth,(req,res)=>{
 const {service,authority,location,matter}=req.body;if(!service||!matter)return res.status(400).json({error:"Service and matter are required."});
 const d=db(),amount=pricing[service]||499,r={id:makeId("CA"),customerId:req.user.id,createdAt:new Date().toISOString(),service,authority:authority||"",location:location||"",matter,status:"New",paymentStatus:"Pending",amount,files:[]};d.requests.unshift(r);save(d);res.json({ok:true,request:r});
});
app.get("/api/my/requests",auth,(req,res)=>res.json(db().requests.filter(r=>r.customerId===req.user.id)));
app.get("/api/my/requests/:id",auth,(req,res)=>{const r=db().requests.find(x=>x.id===req.params.id&&x.customerId===req.user.id);if(!r)return res.status(404).json({error:"Not found"});res.json(r)});

/* Stage 3: private document storage. Files are not served from /public. */
app.post("/api/my/requests/:id/files",auth,upload.array("documents",5),(req,res)=>{
 const d=db(),r=d.requests.find(x=>x.id===req.params.id&&x.customerId===req.user.id);if(!r)return res.status(404).json({error:"Request not found"});
 r.files=(r.files||[]).concat(req.files.map(f=>({id:makeId("FILE"),originalName:f.originalname,storedName:f.filename,size:f.size,mime:f.mimetype,uploadedAt:new Date().toISOString()})));save(d);res.json({ok:true,files:r.files});
});
app.get("/api/my/requests/:id/files/:fileId",auth,(req,res)=>{
 const d=db(),r=d.requests.find(x=>x.id===req.params.id&&x.customerId===req.user.id);if(!r)return res.status(404).end();const f=r.files.find(x=>x.id===req.params.fileId);if(!f)return res.status(404).end();res.download(path.join(UP,f.storedName),f.originalName);
});

/* Stage 4: Razorpay order creation. Secrets stay server-side. */
app.post("/api/payments/create-order",auth,async(req,res)=>{
 try{
  const d=db(),r=d.requests.find(x=>x.id===req.body.requestId&&x.customerId===req.user.id);if(!r)return res.status(404).json({error:"Request not found"});
  if(r.paymentStatus==="Paid")return res.status(400).json({error:"This request is already paid."});
  if(!process.env.RAZORPAY_KEY_ID||!process.env.RAZORPAY_KEY_SECRET)return res.status(503).json({error:"Payment gateway is not configured yet."});
  const rz=new Razorpay({key_id:process.env.RAZORPAY_KEY_ID,key_secret:process.env.RAZORPAY_KEY_SECRET});
  const order=await rz.orders.create({amount:r.amount*100,currency:"INR",receipt:r.id,notes:{request_id:r.id,customer_id:req.user.id}});
  r.razorpayOrderId=order.id;d.payments.push({requestId:r.id,orderId:order.id,amount:r.amount,currency:"INR",status:"created",createdAt:new Date().toISOString()});save(d);
  res.json({keyId:process.env.RAZORPAY_KEY_ID,orderId:order.id,amount:r.amount,currency:"INR",requestId:r.id,customer:{name:req.user.name,email:req.user.email,phone:req.user.phone}});
 }catch(e){console.error(e);res.status(500).json({error:"Unable to create payment order."})}
});
app.post("/api/payments/verify",auth,(req,res)=>{
 const {razorpay_order_id,razorpay_payment_id,razorpay_signature}=req.body,d=db(),r=d.requests.find(x=>x.razorpayOrderId===razorpay_order_id&&x.customerId===req.user.id);
 if(!r)return res.status(404).json({error:"Request not found"});
 if(!process.env.RAZORPAY_KEY_SECRET)return res.status(503).json({error:"Payment gateway is not configured."});
 const expected=crypto.createHmac("sha256",process.env.RAZORPAY_KEY_SECRET).update(razorpay_order_id+"|"+razorpay_payment_id).digest("hex");
 if(!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(razorpay_signature||"")))return res.status(400).json({error:"Payment signature verification failed."});
 r.paymentStatus="Paid";r.paymentId=razorpay_payment_id;r.status=r.status==="New"?"Under Review":r.status;const p=d.payments.find(x=>x.orderId===razorpay_order_id);if(p)p.status="paid";save(d);res.json({ok:true});
});

app.get("/api/owner/requests",owner,(req,res)=>{const d=db();res.json(d.requests.map(r=>({...r,customer:d.users.find(u=>u.id===r.customerId)?.name||"Unknown",email:d.users.find(u=>u.id===r.customerId)?.email||""})))});
app.patch("/api/owner/requests/:id",owner,(req,res)=>{const d=db(),r=d.requests.find(x=>x.id===req.params.id);if(!r)return res.status(404).json({error:"Not found"});if(req.body.status)r.status=req.body.status;save(d);res.json(r)});
app.get("/api/owner/requests/:id/files/:fileId",owner,(req,res)=>{const d=db(),r=d.requests.find(x=>x.id===req.params.id);if(!r)return res.status(404).end();const f=r.files.find(x=>x.id===req.params.fileId);if(!f)return res.status(404).end();res.download(path.join(UP,f.storedName),f.originalName)});
app.get("/api/owner/requests/:id/draft",owner,(req,res)=>{const d=db(),r=d.requests.find(x=>x.id===req.params.id);if(!r)return res.status(404).send("Not found");res.type("html").send(`<!doctype html><html><body style="font-family:Arial;max-width:800px;margin:50px auto;line-height:1.6"><h1>${esc(r.service)}</h1><p><b>Reference:</b> ${esc(r.id)}</p><p><b>Authority:</b> ${esc(r.authority)}</p><p><b>Location:</b> ${esc(r.location)}</p><hr><h3>Customer matter</h3><pre style="white-space:pre-wrap;font:inherit">${esc(r.matter)}</pre><p><i>Drafting/research assistance. Verify facts and applicable requirements before submission.</i></p></body></html>`)});
function esc(s){return String(s||"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
app.use((err,req,res,next)=>{if(err instanceof multer.MulterError||err?.message==="Unsupported file type")return res.status(400).json({error:err.message});next(err)});
app.get("*",(req,res)=>res.sendFile(path.join(BASE,"public","index.html")));
app.listen(PORT,()=>console.log("CivicAssist Stage 3+4 running on http://localhost:"+PORT));