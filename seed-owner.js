const fs=require("fs"),path=require("path"),crypto=require("crypto");
const p=path.join(__dirname,"storage","db.json"),d=JSON.parse(fs.readFileSync(p));
const email=(process.env.OWNER_EMAIL||"owner@example.com").toLowerCase(),name=process.env.OWNER_NAME||"CivicAssist Owner",password=process.env.OWNER_PASSWORD;
if(!password||password.length<12)throw new Error("Set OWNER_PASSWORD to a strong password of at least 12 characters.");
if(d.users.some(u=>u.email===email))throw new Error("Owner already exists.");
const salt=crypto.randomBytes(16).toString("hex"),hash=crypto.scryptSync(password,salt,64).toString("hex");
d.users.push({id:"OWNER-"+crypto.randomBytes(4).toString("hex"),name,email,passwordHash:hash,salt,phone:"",role:"owner",createdAt:new Date().toISOString()});
fs.writeFileSync(p,JSON.stringify(d,null,2));console.log("Owner created:",email);