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
function clearChat(){document.getElementById("chatout").textContent="Response will appear here…"}
async function copyText(t){try{await navigator.clipboard.writeText(t);alert("Copied")}catch(e){alert(t)}}
document.addEventListener("DOMContentLoaded",function(){
  document.getElementById("sendChat")?.addEventListener("click",chat);
  document.getElementById("clearChat")?.addEventListener("click",clearChat);
  document.getElementById("copyKeys")?.addEventListener("click",function(){copyText("POST /v1/keys")});
  document.getElementById("refreshHealth")?.addEventListener("click",loadHealth);
  loadHealth();
});