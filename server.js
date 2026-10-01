import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import crypto from "node:crypto";
import pg from "pg";
import path from "node:path";
import { fileURLToPath } from "node:url";

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
const PREFIX = process.env.BHAI_API_KEY_PREFIX || "bhai_live_";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-3.8-flash";
const GEMINI_FALLBACK_MODELS = String(process.env.GEMINI_FALLBACK_MODELS || "gemini-3.7-flash,gemini-3.5-flash-lite").split(",").map(x=>x.trim()).filter(Boolean);
const IMAGE_FALLBACK_MODELS = String(process.env.IMAGE_FALLBACK_MODELS || "gemini-3.1-flash-image").split(",").map(x=>x.trim()).filter(Boolean).map(x=>x==="gemini-image"?"gemini-3.1-flash-image":x);
const IMAGE_PROVIDER_URLS = String(process.env.IMAGE_PROVIDER_URLS || "").split(",").map(x=>x.trim()).filter(Boolean);
const VIDEO_PROVIDER_URLS = String(process.env.VIDEO_PROVIDER_URLS || "").split(",").map(x=>x.trim()).filter(Boolean);
const IMAGE_PROVIDER_KEYS = String(process.env.IMAGE_PROVIDER_KEYS || "").split(",").map(x=>x.trim());
const VIDEO_PROVIDER_KEYS = String(process.env.VIDEO_PROVIDER_KEYS || "").split(",").map(x=>x.trim());
const pool = process.env.DATABASE_URL ? new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false},connectionTimeoutMillis:5000}) : null;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({origin:process.env.CORS_ORIGIN || "*"}));
app.use(express.json({limit:"2mb"}));
app.use(express.static(path.join(__dirname,"public")));

function requestId(){return "req_"+crypto.randomBytes(10).toString("hex")}
app.use((req,res,next)=>{const id=req.headers["x-request-id"]||requestId();res.setHeader("x-request-id",id);req.requestId=id;next()});
const memoryKeys=new Map();
const ALLOWED_SCOPES=new Set(["chat","coding","github","image","video","files","search","agent","vision","voice"]);

async function initDb(){if(!pool)return;await pool.query(`
CREATE TABLE IF NOT EXISTS bhai_api_keys(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,key_prefix TEXT NOT NULL,key_hash TEXT NOT NULL UNIQUE,scopes JSONB NOT NULL DEFAULT '[\"chat\"]'::jsonb,status TEXT NOT NULL DEFAULT 'active',usage_count BIGINT NOT NULL DEFAULT 0,last_used_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),revoked_at TIMESTAMPTZ);
CREATE INDEX IF NOT EXISTS idx_bhai_api_keys_hash ON bhai_api_keys(key_hash);`)}
function hashKey(key){return crypto.createHash("sha256").update(key).digest("hex")}
function makeKey(){return PREFIX+crypto.randomBytes(24).toString("base64url")}
function putMemoryKey(raw,name="BHAI Bootstrap Key",scopes=["*"],id="bootstrap"){const record={id,name,keyPrefix:raw.slice(0,18),keyHash:hashKey(raw),scopes,status:"active",usageCount:0};memoryKeys.set(record.keyHash,record);return record}
async function saveKey({name,scopes}){const raw=makeKey();const record={id:crypto.randomUUID(),name,keyPrefix:raw.slice(0,18),keyHash:hashKey(raw),scopes:Array.isArray(scopes)&&scopes.length?scopes:["chat"],status:"active",usageCount:0};if(pool){await dbReady;const r=await pool.query("INSERT INTO bhai_api_keys(name,key_prefix,key_hash,scopes) VALUES ($1,$2,$3,$4::jsonb) RETURNING id,name,key_prefix,scopes,status,usage_count,created_at",[record.name,record.keyPrefix,record.keyHash,JSON.stringify(record.scopes)]);if(r.rowCount!==1)throw new Error("API key was not persisted.");record.id=r.rows[0].id;record.createdAt=r.rows[0].created_at;record.status=r.rows[0].status;record.usageCount=Number(r.rows[0].usage_count||0)}memoryKeys.set(record.keyHash,record);return{key:raw,...record,keyHash:undefined}}
async function authenticate(req,res,next){try{const header=req.headers.authorization||"";const raw=header.startsWith("Bearer ")?header.slice(7).trim():"";if(!raw)return res.status(401).json({error:{type:"authentication_error",message:"Missing Bearer API key."},request_id:req.requestId});const keyHash=hashKey(raw);let record=null;if(pool){try{const result=await pool.query("SELECT id,name,scopes,status,usage_count FROM bhai_api_keys WHERE key_hash=$1 LIMIT 1",[keyHash]);record=result.rows[0]||null;if(record)record.scopes=Array.isArray(record.scopes)?record.scopes:[]}catch(dbErr){console.error("API key DB lookup failed; using memory fallback:",dbErr.message);record=memoryKeys.get(keyHash)}}else{record=memoryKeys.get(keyHash)}if(!record||record.status!=="active")return res.status(401).json({error:{type:"authentication_error",message:"Invalid or revoked API key."},request_id:req.requestId});req.apiKey=record;next()}catch(err){next(err)}}
function requireScope(scope){return(req,res,next)=>{if(!req.apiKey?.scopes?.includes(scope)&&!req.apiKey?.scopes?.includes("*"))return res.status(403).json({error:{type:"permission_error",message:`API key does not have the '${scope}' scope.`},request_id:req.requestId});next()}}
async function recordUsage(req){if(!req.apiKey)return;if(pool&&req.apiKey?.id&&req.apiKey.id!=="bootstrap"&&req.apiKey.id!=="test"){try{await pool.query("UPDATE bhai_api_keys SET usage_count=usage_count+1,last_used_at=NOW() WHERE id=$1",[req.apiKey.id])}catch(err){console.error("Usage recording failed:",err.message)}}else req.apiKey.usageCount=(req.apiKey.usageCount||0)+1}
function normalizeGeminiContents(messages){return messages.filter(m=>m&&m.role!=="system"&&typeof m.content==="string").map(m=>({role:m.role==="assistant"?"model":"user",parts:[{text:m.content}]}))}
function getSystemInstruction(messages){const system=messages.filter(m=>m?.role==="system"&&typeof m.content==="string").map(m=>m.content.trim()).filter(Boolean).join("\n\n");return system||null}
async function callGemini({messages,model,generationConfig}){if(!process.env.GEMINI_API_KEY){const e=new Error("GEMINI_API_KEY is not configured.");e.code="provider_not_configured";throw e}const contents=normalizeGeminiContents(messages);if(!contents.length){const e=new Error("No usable user/assistant messages were provided.");e.code="invalid_request";throw e}const models=[...new Set([model,...GEMINI_FALLBACK_MODELS])];let lastError=null;for(const candidateModel of models){const body={contents};const systemInstruction=getSystemInstruction(messages);if(systemInstruction)body.systemInstruction={parts:[{text:systemInstruction}]};if(generationConfig&&typeof generationConfig==="object")body.generationConfig=generationConfig;try{const response=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(candidateModel)}:generateContent`,{method:"POST",headers:{"Content-Type":"application/json","x-goog-api-key":process.env.GEMINI_API_KEY},body:JSON.stringify(body)});const data=await response.json().catch(()=>({}));if(!response.ok){const e=new Error(data?.error?.message||`Gemini returned HTTP ${response.status}`);e.code="provider_error";e.status=response.status;e.provider="gemini";e.model=candidateModel;lastError=e;if(![400,401,403,404,408,409,429,500,502,503,504].includes(response.status))throw e;continue}const text=(data?.candidates||[]).flatMap(c=>c?.content?.parts||[]).map(p=>p?.text).filter(Boolean).join("\n");if(!text){const e=new Error("Gemini returned an empty response.");e.code="provider_error";e.status=502;e.provider="gemini";e.model=candidateModel;lastError=e;continue}return{text,raw:data,model:candidateModel}}catch(err){lastError=err;if(err.code!=="provider_error")throw err}}throw lastError||new Error("All Gemini models failed.")}
app.get("/",(_req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/health",(_req,res)=>res.status(200).json({ok:true,service:"BHAI API",version:"1.0.0"}));
app.get("/v1/health",(_req,res)=>res.json({ok:true,service:"BHAI API",api_version:"v1",database:Boolean(pool),gemini_configured:Boolean(process.env.GEMINI_API_KEY),bootstrap_key_configured:Boolean(process.env.BHAI_BOOTSTRAP_API_KEY),test_key_configured:Boolean(process.env.BHAI_TEST_API_KEY),timestamp:new Date().toISOString()}));
app.post("/v1/keys",async(req,res,next)=>{try{const admin=req.headers["x-bhai-admin-key"];if(!process.env.BHAI_ADMIN_KEY||admin!==process.env.BHAI_ADMIN_KEY)return res.status(401).json({error:{type:"authentication_error",message:"Admin key required."},request_id:req.requestId});const name=String(req.body?.name||"Developer Key").slice(0,120);const scopes=(Array.isArray(req.body?.scopes)?req.body.scopes:["chat"]).map(String).filter(x=>ALLOWED_SCOPES.has(x));const created=await saveKey({name,scopes});if(pool){const check=await pool.query("SELECT id,status FROM bhai_api_keys WHERE key_hash=$1 LIMIT 1",[hashKey(created.key)]);if(check.rowCount!==1||check.rows[0].status!=="active")throw new Error("New API key failed persistence verification.");}res.status(201).json({object:"api_key",key:created.key,name:created.name,scopes:created.scopes,created_at:new Date().toISOString()})}catch(err){next(err)}});

app.get("/v1/keys",async(req,res,next)=>{try{const admin=req.headers["x-bhai-admin-key"];if(!process.env.BHAI_ADMIN_KEY||admin!==process.env.BHAI_ADMIN_KEY)return res.status(401).json({error:{type:"authentication_error",message:"Admin key required."},request_id:req.requestId});if(pool){const r=await pool.query("SELECT id,name,key_prefix,scopes,status,usage_count,last_used_at,created_at,revoked_at FROM bhai_api_keys ORDER BY created_at DESC");return res.json({object:"list",data:r.rows})}res.json({object:"list",data:[...memoryKeys.values()].filter(x=>x.id!=="bootstrap"&&x.id!=="test").map(x=>({id:x.id,name:x.name,key_prefix:x.keyPrefix,scopes:x.scopes,status:x.status,usage_count:x.usageCount||0,created_at:null}))})}catch(err){next(err)}});

app.post("/v1/keys/:id/revoke",async(req,res,next)=>{try{const admin=req.headers["x-bhai-admin-key"];if(!process.env.BHAI_ADMIN_KEY||admin!==process.env.BHAI_ADMIN_KEY)return res.status(401).json({error:{type:"authentication_error",message:"Admin key required."},request_id:req.requestId});if(pool){const r=await pool.query("UPDATE bhai_api_keys SET status='revoked',revoked_at=NOW() WHERE id=$1 RETURNING id,status,revoked_at",[req.params.id]);if(!r.rowCount)return res.status(404).json({error:{type:"not_found",message:"API key not found."},request_id:req.requestId});for(const [hash,k] of memoryKeys){if(String(k.id)===String(req.params.id)){memoryKeys.delete(hash);break}}return res.json({object:"api_key",...r.rows[0]})}let found=null;for(const [hash,k] of memoryKeys){if(String(k.id)===String(req.params.id)){k.status="revoked";memoryKeys.set(hash,k);found=k;break}}if(!found)return res.status(404).json({error:{type:"not_found",message:"API key not found."},request_id:req.requestId});res.json({object:"api_key",id:found.id,status:"revoked"})}catch(err){next(err)}});

app.get("/v1/usage",authenticate,async(req,res,next)=>{try{if(pool&&req.apiKey?.id&&req.apiKey.id!=="bootstrap"&&req.apiKey.id!=="test"){const r=await pool.query("SELECT usage_count,last_used_at,created_at,status FROM bhai_api_keys WHERE id=$1",[req.apiKey.id]);return res.json({object:"usage",key_id:req.apiKey.id,...(r.rows[0]||{})})}res.json({object:"usage",key_id:req.apiKey.id,usage_count:req.apiKey.usageCount||0,last_used_at:null,created_at:null,status:req.apiKey.status})}catch(err){next(err)}});

// ---- Unified capability layer ----
const JOBS=new Map();
const ERRORS=[];
const ERROR_TTL_MS=24*60*60*1000;
function recordError(req,err,status=500){const item={request_id:req?.requestId||null,type:err?.code||"internal_error",message:String(err?.message||err),status,provider:err?.provider||null,path:req?.path||null,method:req?.method||null,timestamp:new Date().toISOString()};ERRORS.unshift(item);if(ERRORS.length>200)ERRORS.length=200;setTimeout(()=>{const i=ERRORS.indexOf(item);if(i>=0)ERRORS.splice(i,1)},ERROR_TTL_MS).unref?.();return item;}
const JOB_TTL_MS=24*60*60*1000;
function makeJob(type,input){const id="job_"+crypto.randomBytes(10).toString("hex");const job={id,type,status:"queued",created_at:new Date().toISOString(),input};JOBS.set(id,job);setTimeout(()=>JOBS.delete(id),JOB_TTL_MS).unref?.();return job}
function capability(name,configured,details={}){return {name,configured,...details}}
app.get("/v1/models",authenticate,async(req,res)=>res.json({object:"list",data:[
  {id:GEMINI_MODEL,provider:"gemini",type:"chat",status:process.env.GEMINI_API_KEY?"ready":"not_configured"},
  {id:process.env.GEMINI_IMAGE_MODEL||"gemini-image",provider:"gemini",type:"image",status:process.env.GEMINI_API_KEY?"available_if_quota":"not_configured"},
  {id:"github",provider:"github",type:"tool",status:process.env.GITHUB_TOKEN?"ready":"not_configured"}
]}));
app.get("/v1/providers",authenticate,async(req,res)=>res.json({object:"providers",data:[
  capability("gemini",Boolean(process.env.GEMINI_API_KEY),{models:[GEMINI_MODEL,...GEMINI_FALLBACK_MODELS]}),
  capability("github",Boolean(process.env.GITHUB_TOKEN)),
  capability("image",Boolean(process.env.GEMINI_API_KEY||process.env.IMAGE_API_URL||process.env.IMAGE_PROVIDER_URLS||process.env.PIXAZO_API_KEY),{providers:[...(process.env.PIXAZO_API_KEY?["pixazo"]:[]),...(process.env.IMAGE_API_URL?["configured"]:[]),...IMAGE_PROVIDER_URLS.map((_,i)=>"fallback_"+(i+1)),...(process.env.GEMINI_API_KEY?["gemini"]:[])]}),
  capability("video",Boolean(process.env.VIDEO_API_URL||process.env.VIDEO_PROVIDER_URLS||process.env.PIXAZO_API_KEY),{providers:[...(process.env.PIXAZO_API_KEY?["pixazo"]:[]),...(process.env.VIDEO_API_URL?["configured"]:[]),...VIDEO_PROVIDER_URLS.map((_,i)=>"fallback_"+(i+1))]}),
  capability("search",Boolean(process.env.SEARCH_API_URL)),
  capability("files",Boolean(process.env.FILES_API_URL)),
  capability("vision",Boolean(process.env.VISION_API_URL||process.env.GEMINI_API_KEY)),
  capability("voice",Boolean(process.env.VOICE_API_URL))
]}));
app.post("/v1/coding",authenticate,requireScope("coding"),async(req,res,next)=>{try{
  const prompt=String(req.body?.prompt||req.body?.message||"").trim(); if(!prompt)return res.status(400).json({error:{type:"invalid_request_error",message:"prompt is required."},request_id:req.requestId});
  const result=await callGemini({messages:[{role:"system",content:"You are BHAI Coding. Diagnose bugs, propose exact fixes, and return complete copy-paste-ready code when code is requested."},{role:"user",content:prompt}],model:String(req.body?.model||GEMINI_MODEL)});
  await recordUsage(req); res.json({object:"coding.completion",provider:"gemini",model:result.model,content:result.text,status:"completed",request_id:req.requestId});
}catch(err){next(err)}});
app.post("/v1/agent",authenticate,requireScope("agent"),async(req,res,next)=>{try{
  const task=String(req.body?.task||req.body?.prompt||"").trim(); if(!task)return res.status(400).json({error:{type:"invalid_request_error",message:"task is required."},request_id:req.requestId});
  const job=makeJob("agent",{task}); job.status="running";
  const result=await callGemini({messages:[{role:"system",content:"You are BHAI Agent. Plan the task, identify risks, produce concrete steps, and only claim completion when verification evidence is available."},{role:"user",content:task}],model:String(req.body?.model||GEMINI_MODEL)});
  job.status="completed"; job.output=result.text; job.model=result.model; job.completed_at=new Date().toISOString(); await recordUsage(req);
  res.json({object:"agent.run",job});
}catch(err){next(err)}});
app.get("/v1/jobs/:id",authenticate,async(req,res)=>{const job=JOBS.get(req.params.id);if(!job)return res.status(404).json({error:{type:"not_found",message:"Job not found."},request_id:req.requestId});res.json(job)});
app.get("/v1/errors",async(req,res)=>{const admin=req.headers["x-bhai-admin-key"];if(!process.env.BHAI_ADMIN_KEY||admin!==process.env.BHAI_ADMIN_KEY)return res.status(401).json({error:{type:"authentication_error",message:"Admin key required."},request_id:req.requestId});res.json({object:"error_log",data:ERRORS.slice(0,100)})});
app.get("/v1/capabilities",authenticate,async(req,res)=>res.json({object:"capabilities",api_version:"v1",database:Boolean(pool),providers:[
  {name:"gemini",configured:Boolean(process.env.GEMINI_API_KEY),models:[GEMINI_MODEL,...GEMINI_FALLBACK_MODELS]},
  {name:"github",configured:Boolean(process.env.GITHUB_TOKEN)},
  {name:"image",configured:Boolean(process.env.IMAGE_API_URL||process.env.IMAGE_PROVIDER_URLS||process.env.PIXAZO_API_KEY||process.env.GEMINI_API_KEY)},
  {name:"video",configured:Boolean(process.env.VIDEO_API_URL||process.env.VIDEO_PROVIDER_URLS||process.env.PIXAZO_API_KEY)},
  {name:"search",configured:Boolean(process.env.SEARCH_API_URL)},
  {name:"files",configured:Boolean(process.env.FILES_API_URL)},
  {name:"vision",configured:Boolean(process.env.VISION_API_URL||process.env.GEMINI_API_KEY)},
  {name:"voice",configured:Boolean(process.env.VOICE_API_URL)}
]}));
async function callGeminiVision({prompt,imageBase64,mimeType="image/png",model}){if(!process.env.GEMINI_API_KEY){const e=new Error("GEMINI_API_KEY is not configured.");e.code="provider_not_configured";throw e}const models=[...new Set([model,...GEMINI_FALLBACK_MODELS])];let lastError=null;for(const candidateModel of models){try{const response=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(candidateModel)}:generateContent`,{method:"POST",headers:{"Content-Type":"application/json","x-goog-api-key":process.env.GEMINI_API_KEY},body:JSON.stringify({contents:[{role:"user",parts:[{text:prompt},{inlineData:{mimeType,data:imageBase64}}]}]})});const data=await response.json().catch(()=>({}));if(!response.ok){const e=new Error(data?.error?.message||`Gemini vision HTTP ${response.status}`);e.code="provider_error";e.status=response.status;e.provider="gemini";e.model=candidateModel;lastError=e;if([400,401,403,404,408,409,429,500,502,503,504].includes(response.status))continue;throw e}const text=(data?.candidates||[]).flatMap(x=>x?.content?.parts||[]).map(x=>x?.text).filter(Boolean).join("\n");if(!text){const e=new Error("Gemini vision returned an empty response.");e.code="provider_error";e.status=502;e.provider="gemini";e.model=candidateModel;lastError=e;continue}return{text,raw:data,model:candidateModel}}catch(err){lastError=err;if(err.code!=="provider_error")throw err}}throw lastError||new Error("All Gemini vision models failed.")}

async function generateGeminiImage({prompt,model,size}){if(!process.env.GEMINI_API_KEY){const e=new Error("GEMINI_API_KEY is not configured.");e.code="provider_not_configured";throw e}const models=[...new Set([model,...IMAGE_FALLBACK_MODELS].filter(Boolean))];let lastError=null;for(const candidateModel of models){try{const response=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(candidateModel)}:generateContent`,{method:"POST",headers:{"Content-Type":"application/json","x-goog-api-key":process.env.GEMINI_API_KEY},body:JSON.stringify({contents:[{role:"user",parts:[{text:prompt}]}],generationConfig:{responseModalities:["TEXT","IMAGE"],imageConfig:{imageSize:size}}})});const data=await response.json().catch(()=>({}));if(!response.ok){const e=new Error(data?.error?.message||`Gemini image HTTP ${response.status}`);e.code="provider_error";e.status=response.status;e.provider="gemini";e.model=candidateModel;lastError=e;if([400,401,403,404,408,409,429,500,502,503,504].includes(response.status))continue;throw e}const parts=(data?.candidates||[]).flatMap(c=>c?.content?.parts||[]);const images=parts.filter(p=>p?.inlineData?.data).map(p=>({mime_type:p.inlineData.mimeType||"image/png",base64:p.inlineData.data}));const text=parts.map(p=>p?.text).filter(Boolean).join("\n");if(!images.length){const e=new Error("Gemini image provider returned no image data.");e.code="provider_error";e.status=502;e.provider="gemini";e.model=candidateModel;lastError=e;continue}return{provider:"gemini",model:candidateModel,images,text,raw:data}}catch(err){lastError=err;if(err.code!=="provider_error")throw err}}throw lastError||new Error("All Gemini image models failed.")}

async function genericProviderPost(url,key,body,extraHeaders={}){
  const r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json",...(key?{"Authorization":"Bearer "+key}:{}),...extraHeaders},body:JSON.stringify(body)});
  const d=await r.json().catch(()=>({}));
  if(!r.ok){const e=new Error(d?.error?.message||d?.message||("Provider HTTP "+r.status));e.code="provider_error";e.status=r.status;throw e}
  return d;
}
function providerFailedStatus(status){return [400,401,402,403,408,409,425,429,500,502,503,504].includes(Number(status))}
function providerList(kind){
  const isImage=kind==="image";
  const urls=isImage?IMAGE_PROVIDER_URLS:VIDEO_PROVIDER_URLS;
  const keys=isImage?IMAGE_PROVIDER_KEYS:VIDEO_PROVIDER_KEYS;
  return urls.map((url,i)=>({url,key:keys[i]||keys[0]||"",name:isImage?"image_provider_"+(i+1):"video_provider_"+(i+1)}));
}
async function tryExternalProviders(kind,body){
  const providers=providerList(kind);
  let last=null;
  for(const p of providers){
    try{
      const d=await genericProviderPost(p.url,p.key,body);
      return {provider:p.name,data:d};
    }catch(err){
      last=err;
      if(!providerFailedStatus(err.status))throw err;
    }
  }
  if(last)throw last;
  return null;
}
app.post("/v1/image",authenticate,requireScope("image"),async(req,res,next)=>{try{
  const prompt=String(req.body?.prompt||"").trim();if(!prompt)return res.status(400).json({error:{type:"invalid_request_error",message:"prompt is required."},request_id:req.requestId});
  const size=String(req.body?.size||"1024x1024");
  const external=[];
  if(process.env.IMAGE_API_URL)external.push({url:process.env.IMAGE_API_URL,key:process.env.IMAGE_API_KEY||"",name:"configured_image_provider"});
  if(process.env.PIXAZO_API_KEY){
    external.push({url:"https://gateway.pixazo.ai/flux/text-to-image",key:"",pixazo_key:process.env.PIXAZO_API_KEY,name:"pixazo_flux_schnell",pixazo:true});
    external.push({url:"https://gateway.pixazo.ai/sd3-5/v1/r-sd-3-5-large",key:"",pixazo_key:process.env.PIXAZO_API_KEY,name:"pixazo_sd3_5",pixazo_sd:true});
  }
  external.push(...providerList("image"));
  let lastError=null;
  const attempts=[];
  for(const p of external){
    try{
      const body=p.pixazo_sd?{prompt,aspect_ratio:"1:1",output_format:"png",output_quality:90}:{p.pixazo?{prompt}:{prompt,model:String(req.body?.model||process.env.IMAGE_MODEL||"image"),size};
      const headers=(p.pixazo||p.pixazo_sd)?{"Ocp-Apim-Subscription-Key":p.pixazo_key,"Cache-Control":"no-cache"}:{};
      const d=await genericProviderPost(p.url,p.key,body,headers);
      await recordUsage(req);return res.json({object:"image.generation",provider:p.name,data:d,status:d?.status||"completed",request_id:req.requestId});
    }catch(err){
      lastError=err;
      attempts.push({provider:p.name,status:err?.status||null,message:String(err?.message||err)});
      if(!providerFailedStatus(err.status))break;
    }
  }
  if(process.env.GEMINI_API_KEY && String(process.env.IMAGE_ALLOW_GEMINI_FALLBACK||"false").toLowerCase()==="true"){
    try{
      const result=await generateGeminiImage({prompt,model:String(req.body?.model||process.env.GEMINI_IMAGE_MODEL||IMAGE_FALLBACK_MODELS[0]||"gemini-3.1-flash-image").replace(/^gemini-image$/,"gemini-3.1-flash-image"),size});
      await recordUsage(req);return res.json({object:"image.generation",provider:result.provider,model:result.model,data:result.images,text:result.text||null,status:"completed",request_id:req.requestId});
    }catch(err){lastError=err;attempts.push({provider:"gemini",status:err?.status||null,message:String(err?.message||err),model:err?.model||null});}
  }
  if(lastError){recordError(req,lastError,502);return res.status(502).json({error:{type:"provider_error",provider:lastError.provider||"image_router",message:lastError.message,attempts},request_id:req.requestId});}
  return res.status(503).json({error:{type:"provider_not_configured",message:"No image provider is configured. Add PIXAZO_API_KEY or IMAGE_API_URL(S)."},request_id:req.requestId});
}catch(err){recordError(req,err,500);next(err)}});
app.post("/v1/video",authenticate,requireScope("video"),async(req,res,next)=>{try{
  const prompt=String(req.body?.prompt||"").trim();if(!prompt)return res.status(400).json({error:{type:"invalid_request_error",message:"prompt is required."},request_id:req.requestId});
  const duration=Math.min(20,Math.max(1,Number(req.body?.duration||5)));
  const providers=[];
  if(process.env.VIDEO_API_URL)providers.push({url:process.env.VIDEO_API_URL,key:process.env.VIDEO_API_KEY||"",name:"configured_video_provider"});
  if(process.env.PIXAZO_API_KEY)providers.push({url:"https://gateway.pixazo.ai/ltx/text-to-video",key:"",pixazo_key:process.env.PIXAZO_API_KEY,name:"pixazo_ltx",pixazo:true});
  providers.push(...providerList("video"));
  let lastError=null;
  for(const p of providers){
    try{
      const body=p.pixazo?{prompt}:{prompt,model:String(req.body?.model||process.env.VIDEO_MODEL||"video"),duration,aspect_ratio:String(req.body?.aspect_ratio||"16:9")};
      const headers=p.pixazo?{"Ocp-Apim-Subscription-Key":p.pixazo_key,"Cache-Control":"no-cache"}: {};
      const d=await genericProviderPost(p.url,p.key,body,headers);
      await recordUsage(req);return res.json({object:"video.generation",provider:p.name,data:d,status:d?.status||"submitted",request_id:req.requestId});
    }catch(err){lastError=err;if(!providerFailedStatus(err.status))break;}
  }
  if(lastError){recordError(req,lastError,502);return res.status(502).json({error:{type:"provider_error",provider:lastError.provider||"video",message:lastError.message},request_id:req.requestId});}
  return res.status(503).json({error:{type:"provider_not_configured",message:"No video provider is configured. Add PIXAZO_API_KEY or VIDEO_API_URL(S)."},request_id:req.requestId});
}catch(err){recordError(req,err,500);next(err)}});
app.get("/v1/github/me",authenticate,requireScope("github"),async(req,res,next)=>{try{
  if(!process.env.GITHUB_TOKEN)return res.status(503).json({error:{type:"provider_not_configured",message:"GITHUB_TOKEN is not configured."},request_id:req.requestId});
  const r=await fetch("https://api.github.com/user",{headers:{Authorization:"Bearer "+process.env.GITHUB_TOKEN,Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"BHAI-API"}});
  const d=await r.json();if(!r.ok)return res.status(502).json({error:{type:"provider_error",provider:"github",message:d?.message||("GitHub HTTP "+r.status)},request_id:req.requestId});
  res.json({object:"github.user",data:{login:d.login,id:d.id,name:d.name,avatar_url:d.avatar_url,html_url:d.html_url}});
}catch(err){next(err)}});
app.post("/v1/github/repos",authenticate,requireScope("github"),async(req,res,next)=>{try{
  if(!process.env.GITHUB_TOKEN)return res.status(503).json({error:{type:"provider_not_configured",message:"GITHUB_TOKEN is not configured."},request_id:req.requestId});
  const name=String(req.body?.name||"").trim();if(!/^[A-Za-z0-9_.-]{1,100}$/.test(name))return res.status(400).json({error:{type:"invalid_request_error",message:"Valid repository name is required."},request_id:req.requestId});
  const r=await fetch("https://api.github.com/user/repos",{method:"POST",headers:{Authorization:"Bearer "+process.env.GITHUB_TOKEN,Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"BHAI-API","Content-Type":"application/json"},body:JSON.stringify({name,description:String(req.body?.description||"Created by BHAI API").slice(0,350),private:Boolean(req.body?.private),auto_init:true})});
  const d=await r.json();if(!r.ok)return res.status(502).json({error:{type:"provider_error",provider:"github",message:d?.message||("GitHub HTTP "+r.status)},request_id:req.requestId});
  await recordUsage(req);res.status(201).json({object:"github.repository",data:{name:d.name,full_name:d.full_name,private:d.private,default_branch:d.default_branch,url:d.html_url},request_id:req.requestId});
}catch(err){next(err)}});
app.get("/v1/github/repos",authenticate,requireScope("github"),async(req,res,next)=>{try{
  if(!process.env.GITHUB_TOKEN)return res.status(503).json({error:{type:"provider_not_configured",message:"GITHUB_TOKEN is not configured."},request_id:req.requestId});
  const r=await fetch("https://api.github.com/user/repos?per_page=100",{headers:{Authorization:"Bearer "+process.env.GITHUB_TOKEN,Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"BHAI-API"}});
  const d=await r.json(); if(!r.ok)return res.status(502).json({error:{type:"provider_error",provider:"github",message:d?.message||("GitHub HTTP "+r.status)},request_id:req.requestId});
  res.json({object:"list",data:d.map(x=>({name:x.name,full_name:x.full_name,private:x.private,default_branch:x.default_branch,url:x.html_url}))});
}catch(err){next(err)}});
app.post("/v1/search",authenticate,requireScope("search"),async(req,res,next)=>{try{
  if(!process.env.SEARCH_API_URL)return res.status(503).json({error:{type:"provider_not_configured",message:"SEARCH_API_URL is not configured."},request_id:req.requestId});
  const d=await genericProviderPost(process.env.SEARCH_API_URL,process.env.SEARCH_API_KEY,{query:String(req.body?.query||"").trim(),limit:Number(req.body?.limit||10)});
  await recordUsage(req);res.json({object:"search.results",provider:"configured_search_provider",data:d,request_id:req.requestId});
}catch(err){recordError(req,err,502);next(err)}});
app.post("/v1/vision",authenticate,requireScope("vision"),async(req,res,next)=>{try{
  const prompt=String(req.body?.prompt||"Describe/analyze this image.").trim(); const image=String(req.body?.image_base64||"").trim();
  if(!image)return res.status(400).json({error:{type:"invalid_request_error",message:"image_base64 is required."},request_id:req.requestId});
  if(!process.env.GEMINI_API_KEY&&!process.env.VISION_API_URL)return res.status(503).json({error:{type:"provider_not_configured",message:"No vision provider is configured."},request_id:req.requestId});
  if(process.env.VISION_API_URL){const d=await genericProviderPost(process.env.VISION_API_URL,process.env.VISION_API_KEY,{prompt,image_base64:image});await recordUsage(req);return res.json({object:"vision.completion",provider:"configured_vision_provider",data:d,status:"completed",request_id:req.requestId});}
  const result=await callGeminiVision({prompt,imageBase64:image,mimeType:String(req.body?.mime_type||"image/png"),model:String(req.body?.model||GEMINI_MODEL)});await recordUsage(req);res.json({object:"vision.completion",provider:"gemini",model:result.model,content:result.text,status:"completed",request_id:req.requestId});
}catch(err){recordError(req,err,502);next(err)}});
app.post("/v1/files",authenticate,requireScope("files"),async(req,res,next)=>{try{
  if(!process.env.FILES_API_URL)return res.status(503).json({error:{type:"provider_not_configured",message:"FILES_API_URL is not configured."},request_id:req.requestId});
  const d=await genericProviderPost(process.env.FILES_API_URL,process.env.FILES_API_KEY,req.body||{});await recordUsage(req);res.json({object:"file.operation",provider:"configured_files_provider",data:d,status:"completed",request_id:req.requestId});
}catch(err){recordError(req,err,502);next(err)}});
app.post("/v1/voice",authenticate,requireScope("voice"),async(req,res,next)=>{try{
  if(!process.env.VOICE_API_URL)return res.status(503).json({error:{type:"provider_not_configured",message:"VOICE_API_URL is not configured."},request_id:req.requestId});
  const d=await genericProviderPost(process.env.VOICE_API_URL,process.env.VOICE_API_KEY,req.body||{});await recordUsage(req);res.json({object:"voice.operation",provider:"configured_voice_provider",data:d,status:"completed",request_id:req.requestId});
}catch(err){recordError(req,err,502);next(err)}});

app.post("/v1/chat",authenticate,requireScope("chat"),async(req,res,next)=>{try{const messages=Array.isArray(req.body?.messages)?req.body.messages:[];if(!messages.length)return res.status(400).json({error:{type:"invalid_request_error",message:"messages is required."},request_id:req.requestId});const model=String(req.body?.model||GEMINI_MODEL);const result=await callGemini({messages,model,generationConfig:req.body?.generationConfig});await recordUsage(req);res.json({id:"chat_"+crypto.randomBytes(10).toString("hex"),object:"chat.completion",created:Math.floor(Date.now()/1000),provider:"gemini",model:result.model||model,choices:[{index:0,message:{role:"assistant",content:result.text},finish_reason:result.raw?.candidates?.[0]?.finishReason||"STOP"}],usage:result.raw?.usageMetadata||null,status:"completed",request_id:req.requestId})}catch(err){if(err.code==="invalid_request")return res.status(400).json({error:{type:"invalid_request_error",message:err.message},request_id:req.requestId});if(err.code==="provider_not_configured")return res.status(503).json({error:{type:"provider_not_configured",message:"Gemini provider is not configured on BHAI API."},request_id:req.requestId});if(err.code==="provider_error")return res.status(502).json({error:{type:"provider_error",provider:err.provider,message:err.message},request_id:req.requestId});next(err)}});
app.use((_req,res)=>res.status(404).json({error:{type:"not_found",message:"Route not found."}}));
app.use((err,req,res,_next)=>{recordError(req,err,500);console.error("BHAI API error:",err);res.status(500).json({error:{type:"internal_error",message:"Internal server error."},request_id:req.requestId})});
process.on("unhandledRejection",err=>console.error("Unhandled rejection:",err));process.on("uncaughtException",err=>console.error("Uncaught exception:",err));
const server=app.listen(PORT,HOST,()=>console.log(`BHAI API listening on http://${HOST}:${PORT}`));server.on("error",err=>console.error("HTTP server failed to start:",err));
if(process.env.BHAI_BOOTSTRAP_API_KEY)putMemoryKey(process.env.BHAI_BOOTSTRAP_API_KEY,"BHAI Owner Key",["*"],"bootstrap");
if(process.env.BHAI_TEST_API_KEY)putMemoryKey(process.env.BHAI_TEST_API_KEY,"BHAI API Test Key",["chat"],"test");
const dbReady=initDb().then(()=>console.log("BHAI API database initialization complete")).catch(err=>{console.error("Database initialization deferred:",err.message);return null});
