async function loadHealth(){
  const out=document.getElementById("healthout");
  try{
    const r=await fetch("/v1/health",{cache:"no-store"}); const d=await r.json();
    const gemini=document.getElementById("gemini"), db=document.getElementById("db"), status=document.getElementById("status");
    if(gemini) gemini.textContent=d.gemini_configured?"READY":"OFF";
    if(db) db.textContent=d.database?"CONNECTED":"NOT CONNECTED";
    status.textContent=d.ok?"ONLINE":"ERROR"; status.className="badge "+(d.ok?"ok":"bad");
    if(out) out.textContent=JSON.stringify(d,null,2);
  }catch(e){
    const status=document.getElementById("status"); status.textContent="OFFLINE"; status.className="badge bad";
    if(out) out.textContent="Health request failed: "+e.message;
  }
}
async function chat(){
  const key=document.getElementById("key").value.trim(), msg=document.getElementById("msg").value.trim(), out=document.getElementById("chatout");
  if(!key){out.textContent="API key required.";return} if(!msg){out.textContent="Message required.";return}
  out.textContent="Thinking…";
  try{
    const r=await fetch("/v1/chat",{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+key},body:JSON.stringify({messages:[{role:"user",content:msg}]})});
    out.textContent=JSON.stringify(await r.json(),null,2);
  }catch(e){out.textContent="Connection error: "+e.message}
}
async function verifyKey(raw){
  const key=String(raw||"").trim(), out=document.getElementById("keyout");
  if(!key){out.textContent="API key missing.";return}
  out.textContent="Testing this exact API key…";
  try{
    const r=await fetch("/v1/chat",{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+key},body:JSON.stringify({messages:[{role:"user",content:"Reply only: BHAI API key OK"}]})});
    const d=await r.json();
    if(r.ok){
      document.getElementById("key").value=key;
      out.innerHTML='<b class="ok">✅ API key verified.</b><pre>'+escapeHtml(JSON.stringify(d,null,2))+'</pre>';
    }else{
      out.innerHTML='<b class="bad">❌ This exact key was rejected.</b><pre>'+escapeHtml(JSON.stringify(d,null,2))+'</pre>';
    }
  }catch(e){out.textContent="Verification failed: "+e.message}
}
function clearChat(){document.getElementById("chatout").textContent="Response will appear here…";const key=document.getElementById("key");if(key)key.value=""}
async function copyText(t){
  const value=String(t??"").trim();
  if(!value)return false;
  const input=document.getElementById("newApiKeyValue");
  if(input && input.value.trim()===value){
    input.focus();
    input.select();
    input.setSelectionRange(0,input.value.length);
  }
  try{
    if(navigator.clipboard && window.isSecureContext){
      await navigator.clipboard.writeText(value);
    }else{
      const ta=document.createElement("textarea");
      ta.value=value;ta.setAttribute("readonly","");
      ta.style.position="fixed";ta.style.left="-9999px";
      document.body.appendChild(ta);ta.focus();ta.select();ta.setSelectionRange(0,value.length);
      const ok=document.execCommand("copy");
      ta.remove();
      if(!ok)throw new Error("copy command failed");
    }
    alert("✅ Full API key copied");
    return true;
  }catch(e){
    if(input && input.value.trim()===value){
      input.focus();input.select();input.setSelectionRange(0,value.length);
      alert("Key selected — tap Copy from your phone's menu.");
      return false;
    }
    prompt("Copy this FULL API key:",value);
    return false;
  }
}
function renderKeyHistory(items){
  const box=document.getElementById("keyhistory"); if(!box)return;
  if(!items.length){box.innerHTML='<div class="notice">No developer keys yet.</div>';return}
  box.innerHTML=items.map(k=>{
    const revoked=k.status!=="active";
    return '<div class="keyrow"><div><b>'+escapeHtml(k.name||"Unnamed key")+'</b><div class="small">'+escapeHtml(k.key_prefix||"")+" • "+escapeHtml(k.status||"unknown")+" • usage "+Number(k.usage_count||0)+'</div></div><button class="secondary revoke-key" data-id="'+escapeAttr(k.id)+'" '+(revoked?'disabled':'')+'>'+ (revoked?'Revoked':'Block / Revoke')+'</button></div>';
  }).join("");
  box.querySelectorAll(".revoke-key").forEach(b=>b.addEventListener("click",()=>revokeKey(b.dataset.id)));
}
function escapeHtml(s){return String(s).replace(/[&<>'"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]))}
function escapeAttr(s){return escapeHtml(s)}
async function adminRequest(path,options={}){const key=document.getElementById("adminKey").value.trim();if(!key)throw new Error("Admin key required.");options.headers={...(options.headers||{}),"x-bhai-admin-key":key,"Content-Type":"application/json"};const r=await fetch(path,options);const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d?.error?.message||("HTTP "+r.status));return d}
async function createKey(){
  const out=document.getElementById("keyout"); out.textContent="Creating…";
  try{
    const scopes=[...document.querySelectorAll(".scope:checked")].map(x=>x.value);
    const d=await adminRequest("/v1/keys",{method:"POST",body:JSON.stringify({name:document.getElementById("keyName").value.trim()||"My App",scopes})});
    out.innerHTML='<b>New API key created — copy it now. It is shown only once.</b><label for="newApiKeyValue">Full API Key</label><input id="newApiKeyValue" class="full-key" type="text" readonly value="'+escapeAttr(d.key)+'" spellcheck="false" autocapitalize="off" autocomplete="off"><button class="primary" id="copyNewKey" type="button">📋 Copy Full API Key</button> <button class="secondary" id="verifyNewKey" type="button">✅ Test This Key</button><pre>'+escapeHtml(JSON.stringify({...d,key:"(shown in the full-key field above)"},null,2))+'</pre>';
    document.getElementById("copyNewKey").addEventListener("click",()=>copyText(d.key));
    document.getElementById("verifyNewKey").addEventListener("click",()=>verifyKey(d.key));
    document.getElementById("key").value=d.key;
    await listKeys();
  }catch(e){out.textContent="Create failed: "+e.message}
}
async function listKeys(){
  const out=document.getElementById("keyout"); out.textContent="Loading key history…";
  try{const d=await adminRequest("/v1/keys");renderKeyHistory(d.data||[]);out.textContent="Key history loaded. Prefix is NOT the secret API key."}
  catch(e){out.textContent="List failed: "+e.message}
}
async function revokeKey(id){if(!confirm("Block/revoke this API key? It will stop working."))return;try{await adminRequest("/v1/keys/"+encodeURIComponent(id),{method:"POST"});await listKeys()}catch(e){alert("Revoke failed: "+e.message)}}
function clearSensitiveInputs(){
  const key=document.getElementById("key"); if(key){key.value="";key.setAttribute("autocomplete","off")}
  const admin=document.getElementById("adminKey"); if(admin) admin.value="";
}
window.addEventListener("pageshow",clearSensitiveInputs);
document.addEventListener("DOMContentLoaded",function(){
  clearSensitiveInputs();
  document.getElementById("sendChat")?.addEventListener("click",chat);
  document.getElementById("clearChat")?.addEventListener("click",clearChat);
  document.getElementById("createKey")?.addEventListener("click",createKey);
  document.getElementById("listKeys")?.addEventListener("click",listKeys);
  document.getElementById("refreshHealth")?.addEventListener("click",loadHealth);
  loadHealth();
});