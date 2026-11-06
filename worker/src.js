import adminHtml from './admin.html';
const DAY=86400;
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers}});
const cookie=(name,value,maxAge)=>`${name}=${encodeURIComponent(value)}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
function cookies(req){return Object.fromEntries((req.headers.get('cookie')||'').split(';').map(s=>s.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2));}
const digest=async s=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))].map(b=>b.toString(16).padStart(2,'0')).join('');
const random=()=>crypto.randomUUID()+crypto.randomUUID();
function originOf(req){return new URL(req.url).origin;}
function cors(req,env){const origin=req.headers.get('Origin');return origin===env.PUBLIC_SITE_ORIGIN||origin==='https://steamcommunity.com'?{'Access-Control-Allow-Origin':origin,'Vary':'Origin'}:{}};
async function readPublic(env){const {results}=await env.DB.prepare('SELECT steamid,nickname FROM players ORDER BY sort_order,steamid').all();const row=await env.DB.prepare("SELECT value FROM settings WHERE key='prefix'").first();return {prefix:row?.value??'MP ',players:results};}
async function auth(req,env){const t=cookies(req).mp_session;if(!t)return false;const hash=await digest(t);const s=await env.DB.prepare('SELECT discord_id FROM sessions WHERE token_hash=? AND expires_at>?').bind(hash,Math.floor(Date.now()/1000)).first();return s?.discord_id===env.ADMIN_DISCORD_ID;}
function redirect(url,headers={}){return new Response(null,{status:302,headers:{Location:url,'Cache-Control':'no-store',...headers}});}

// Discord interaction signatures must be verified before parsing the payload.
const hexBytes = hex => new Uint8Array((hex.match(/.{2}/g)||[]).map(x=>parseInt(x,16)));
async function verifyDiscord(req, raw, env){
 const sig=req.headers.get('X-Signature-Ed25519')||'';
 const ts=req.headers.get('X-Signature-Timestamp')||'';
 if(!/^[a-fA-F0-9]{128}$/.test(sig)||!/^[0-9]{10,13}$/.test(ts)||!/^[a-fA-F0-9]{64}$/.test(env.DISCORD_PUBLIC_KEY||''))return false;
 if(Math.abs(Date.now()/1000-Number(ts))>300)return false;
 try{const key=await crypto.subtle.importKey('raw',hexBytes(env.DISCORD_PUBLIC_KEY),{name:'Ed25519'},false,['verify']);return await crypto.subtle.verify('Ed25519',key,hexBytes(sig),new TextEncoder().encode(ts+raw));}catch(e){console.error('Discord signature verification unavailable',e);return false;}
}
const interactionMessage=(content)=>json({type:4,data:{content,flags:64}});
const snowflake=id=>/^\d{17,20}$/.test(id);
const steamId=id=>/^7656119\d{10}$/.test(id);
async function discordApi(env,path,method='POST',body){const r=await fetch('https://discord.com/api/v10'+path,{method,headers:{Authorization:'Bot '+env.DISCORD_BOT_TOKEN,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});const data=await r.json().catch(()=>({}));if(!r.ok)throw Error('Discord API '+r.status+': '+(data.message||'Request failed'));return data;}
async function inviteDecision(env,inviteId,userId,choice){
 const now=Math.floor(Date.now()/1000);
 const inv=await env.DB.prepare('SELECT * FROM invitations WHERE id=?').bind(inviteId).first();
 if(!inv)return 'Invitation not found.';
 if(inv.discord_id!==userId)return 'This invitation belongs to another Discord account.';
 if(inv.status!=='pending')return 'Invitation status: '+inv.status;
 if(inv.expires_at<=now){await env.DB.prepare("UPDATE invitations SET status='expired',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").bind(inviteId).run();return 'Invitation expired.';}
 if(choice==='decline'){await env.DB.prepare("UPDATE invitations SET status='declined',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").bind(inviteId).run();return 'Invitation declined.';}
 const updated=await env.DB.prepare("UPDATE invitations SET status='awaiting_steam',updated_at=CURRENT_TIMESTAMP WHERE id=? AND discord_id=? AND status='pending' AND expires_at>?").bind(inviteId,userId,now).run();
 return updated.meta.changes===1?'Invitation accepted! Open your personal Steam linking URL from the follow-up DM.':'Invitation already processed.';
}
async function sendLinkDM(env,discordId,invId,base){
 const dm=await discordApi(env,'/users/@me/channels','POST',{recipient_id:discordId});
 return discordApi(env,'/channels/'+dm.id+'/messages','POST',{content:'**MP TEAM — Connect your Steam account**\nYou accepted your invitation. Sign in with Discord and Steam to verify your SteamID64.\n'+base+'/join/'+invId+'\nLink expires with your invitation. Never share this link.',allowed_mentions:{parse:[]}});
}
const htmlEscape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const page=(title,body)=>new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEscape(title)} · MP TEAM</title><style>body{font:16px system-ui;background:#0b1012;color:#f1f5ef;max-width:620px;margin:9vh auto;padding:24px}main{border:1px solid #37453f;border-radius:16px;background:#182021;padding:32px}a{display:inline-block;background:#f17a45;color:#121816;padding:13px 18px;border-radius:9px;font-weight:bold;text-decoration:none}p{line-height:1.6;color:#c4d0c9}</style><main><h1>${htmlEscape(title)}</h1>${body}</main></html>`,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"}});
async function discordOAuthUser(code,redirectUri,env){
 const r=await fetch('https://discord.com/api/v10/oauth2/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:env.DISCORD_CLIENT_ID,client_secret:env.DISCORD_CLIENT_SECRET,grant_type:'authorization_code',code,redirect_uri:redirectUri})});
 if(!r.ok)throw Error('Discord OAuth exchange failed');const token=await r.json();const u=await fetch('https://discord.com/api/v10/users/@me',{headers:{Authorization:'Bearer '+token.access_token}});if(!u.ok)throw Error('Discord identity verification failed');return u.json();
}
async function steamVerify(req,env,expectedReturn){
 const u=new URL(req.url);const params=new URLSearchParams();for(const [k,v] of u.searchParams)if(k.startsWith('openid.'))params.set(k,v);
 if(params.get('openid.mode')!=='id_res'||params.get('openid.ns')!=='http://specs.openid.net/auth/2.0'||params.get('openid.return_to')!==expectedReturn||params.get('openid.op_endpoint')!=='https://steamcommunity.com/openid/login')throw Error('Invalid Steam OpenID assertion');
 const claimed=params.get('openid.claimed_id')||'';const match=claimed.match(/^https:\/\/steamcommunity\.com\/openid\/id\/(7656119\d{10})$/);if(!match||params.get('openid.identity')!==claimed)throw Error('Invalid Steam identity');
 params.set('openid.mode','check_authentication');const r=await fetch('https://steamcommunity.com/openid/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:params});if(!r.ok||!/(?:^|\n)is_valid:true(?:\n|$)/.test(await r.text()))throw Error('Steam did not validate login');return match[1];
}

export default {async fetch(req,env,ctx){try{
 const url=new URL(req.url),path=url.pathname;
 if(path==='/discord/interactions'&&req.method==='POST'){
  const raw=await req.text();if(!await verifyDiscord(req,raw,env))return new Response('Invalid signature',{status:401});
  let event;try{event=JSON.parse(raw)}catch{return new Response('Bad JSON',{status:400})}
  if(event.type===1)return json({type:1});
  if(event.type!==3)return interactionMessage('Unsupported interaction.');
  const custom=String(event.data?.custom_id||'');const match=custom.match(/^mpinv:(accept|decline):([a-f0-9-]{36})$/);
  if(!match)return interactionMessage('Unknown button.');
  const userId=event.user?.id||event.member?.user?.id;
  if(!userId)return interactionMessage('Discord account not found.');
  try{const message=await inviteDecision(env,match[2],userId,match[1]);if(match[1]==='accept'&&message.startsWith('Invitation accepted!'))ctx.waitUntil(sendLinkDM(env,userId,match[2],originOf(req)).catch(e=>console.error('Link DM failed',e)));return interactionMessage(message);}
  catch(e){console.error(e);return interactionMessage('Could not process this invitation. Please contact the admin.');}
 }

 if(req.method==='OPTIONS'&&path==='/api/public'){return new Response(null,{status:204,headers:{...cors(req,env),'Access-Control-Allow-Methods':'GET, OPTIONS','Access-Control-Allow-Headers':'Content-Type','Access-Control-Max-Age':'86400'}});}
 if(path==='/api/public'&&req.method==='GET')return json(await readPublic(env),200,{...cors(req,env),'Cache-Control':'public, max-age=30'});
 const joinMatch=path.match(/^\/join\/([a-f0-9-]{36})$/);
 if(joinMatch&&req.method==='GET'){
  const inv=await env.DB.prepare('SELECT * FROM invitations WHERE id=?').bind(joinMatch[1]).first();
  if(!inv||inv.status!=='awaiting_steam'||inv.expires_at<=Math.floor(Date.now()/1000))return page('Invitation unavailable','<p>This invitation is expired or not awaiting Steam verification.</p>');
  const state=random();await env.DB.prepare('INSERT INTO join_states(state_hash,invite_id,stage,expires_at) VALUES(?,?,?,?)').bind(await digest(state),inv.id,'discord',Math.floor(Date.now()/1000)+600).run();
  const redirectUri=originOf(req)+'/join/discord/callback';const target=new URL('https://discord.com/oauth2/authorize');target.search=new URLSearchParams({client_id:env.DISCORD_CLIENT_ID,response_type:'code',redirect_uri:redirectUri,scope:'identify',state}).toString();
  return page('Join MP TEAM','<p>First confirm the invited Discord account, then sign in through Steam. Your Steam password is never shared with MP TEAM.</p><a href="'+htmlEscape(target.toString())+'">Continue with Discord</a>');
 }
 if(path==='/join/discord/callback'&&req.method==='GET'){
  const state=url.searchParams.get('state')||'',code=url.searchParams.get('code')||'';if(!state||!code)return page('Invalid login','<p>Missing Discord authorization.</p>');
  const row=await env.DB.prepare("SELECT * FROM join_states WHERE state_hash=? AND stage='discord' AND expires_at>?").bind(await digest(state),Math.floor(Date.now()/1000)).first();if(!row)return page('Expired login','<p>Open your invitation link again.</p>');
  await env.DB.prepare('DELETE FROM join_states WHERE state_hash=?').bind(row.state_hash).run();
  const user=await discordOAuthUser(code,originOf(req)+'/join/discord/callback',env);const inv=await env.DB.prepare('SELECT * FROM invitations WHERE id=?').bind(row.invite_id).first();
  if(!inv||inv.discord_id!==user.id||inv.status!=='awaiting_steam'||inv.expires_at<=Math.floor(Date.now()/1000))return page('Access denied','<p>Only the Discord account that received this invitation can link Steam.</p>');
  const nonce=random();await env.DB.prepare('INSERT INTO join_states(state_hash,invite_id,stage,discord_id,expires_at) VALUES(?,?,?,?,?)').bind(await digest(nonce),inv.id,'steam',user.id,Math.floor(Date.now()/1000)+600).run();
  const returnTo=originOf(req)+'/join/steam/callback?state='+encodeURIComponent(nonce);const steam=new URL('https://steamcommunity.com/openid/login');steam.search=new URLSearchParams({'openid.ns':'http://specs.openid.net/auth/2.0','openid.mode':'checkid_setup','openid.return_to':returnTo,'openid.realm':originOf(req),'openid.identity':'http://specs.openid.net/auth/2.0/identifier_select','openid.claimed_id':'http://specs.openid.net/auth/2.0/identifier_select'}).toString();
  return redirect(steam.toString());
 }
 if(path==='/join/steam/callback'&&req.method==='GET'){
  const nonce=url.searchParams.get('state')||'';const row=await env.DB.prepare("SELECT * FROM join_states WHERE state_hash=? AND stage='steam' AND expires_at>?").bind(await digest(nonce),Math.floor(Date.now()/1000)).first();if(!row)return page('Expired login','<p>Open your invitation link again.</p>');
  const steamid=await steamVerify(req,env,originOf(req)+'/join/steam/callback?state='+encodeURIComponent(nonce));
  const inv=await env.DB.prepare('SELECT * FROM invitations WHERE id=?').bind(row.invite_id).first();
  if(!inv||inv.status!=='awaiting_steam'||inv.discord_id!==row.discord_id||inv.expires_at<=Math.floor(Date.now()/1000))return page('Invitation unavailable','<p>This invitation can no longer be used.</p>');
  const linked=await env.DB.prepare('SELECT discord_id FROM steam_links WHERE steamid=?').bind(steamid).first();if(linked&&linked.discord_id!==inv.discord_id)return page('Already linked','<p>This Steam account is linked to another Discord account. Contact your administrator.</p>');
  const discordLink=await env.DB.prepare('SELECT steamid FROM steam_links WHERE discord_id=?').bind(inv.discord_id).first();if(discordLink&&discordLink.steamid!==steamid)return page('Already linked','<p>Your Discord account already has another Steam account linked. Contact your administrator.</p>');
  // Claim the invitation first; conditional update prevents duplicate processing.
  const result=await env.DB.prepare("UPDATE invitations SET status='accepted',steamid=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='awaiting_steam' AND expires_at>?").bind(steamid,inv.id,Math.floor(Date.now()/1000)).run();if(result.meta.changes!==1)return page('Already processed','<p>Invitation already handled.</p>');
  await env.DB.batch([env.DB.prepare('INSERT OR IGNORE INTO steam_links(discord_id,steamid) VALUES(?,?)').bind(inv.discord_id,steamid),env.DB.prepare('INSERT OR IGNORE INTO players(steamid,nickname,sort_order) VALUES(?,?,(SELECT COALESCE(MAX(sort_order),0)+1 FROM players))').bind(steamid,inv.nickname),env.DB.prepare('DELETE FROM join_states WHERE state_hash=?').bind(row.state_hash)]);
  return page('Welcome to MP TEAM','<p>SteamID64 verified and linked: <strong>'+htmlEscape(steamid)+'</strong>.</p><p>Your teammate can now open your Steam profile and send a friend request.</p><a href="https://steamcommunity.com/profiles/'+steamid+'">View Steam profile</a>');
 }
 if(path==='/auth/login'&&req.method==='GET'){
  const state=random();const redirectUri=originOf(req)+'/auth/callback';const target=new URL('https://discord.com/oauth2/authorize');target.search=new URLSearchParams({client_id:env.DISCORD_CLIENT_ID,response_type:'code',redirect_uri:redirectUri,scope:'identify',state,prompt:'consent'}).toString();return redirect(target.toString(),{'Set-Cookie':cookie('mp_oauth_state',state,600)});
 }
 if(path==='/auth/callback'&&req.method==='GET'){
  const cs=cookies(req);const state=url.searchParams.get('state');const code=url.searchParams.get('code');if(!state||!code||state!==cs.mp_oauth_state)return new Response('Invalid OAuth state. Try /auth/login again.',{status:403});
  const redirectUri=originOf(req)+'/auth/callback';const tokenResp=await fetch('https://discord.com/api/v10/oauth2/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:env.DISCORD_CLIENT_ID,client_secret:env.DISCORD_CLIENT_SECRET,grant_type:'authorization_code',code,redirect_uri:redirectUri})});if(!tokenResp.ok)return new Response('Discord login failed.',{status:502});const token=await tokenResp.json();
  const userResp=await fetch('https://discord.com/api/v10/users/@me',{headers:{Authorization:'Bearer '+token.access_token}});if(!userResp.ok)return new Response('Discord profile lookup failed.',{status:502});const user=await userResp.json();if(user.id!==env.ADMIN_DISCORD_ID)return new Response('Access denied: this Discord account is not the MP TEAM administrator.',{status:403,headers:{'Set-Cookie':cookie('mp_oauth_state','',0)}});
  const session=random();await env.DB.prepare('INSERT INTO sessions(token_hash,discord_id,expires_at) VALUES(?,?,?)').bind(await digest(session),user.id,Math.floor(Date.now()/1000)+7*DAY).run();const h=new Headers({Location:'/admin','Cache-Control':'no-store'});h.append('Set-Cookie',cookie('mp_session',session,7*DAY));h.append('Set-Cookie',cookie('mp_oauth_state','',0));return new Response(null,{status:302,headers:h});
 }
 if(path==='/admin'&&req.method==='GET')return new Response(adminHtml,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"}});
 if(path==='/api/admin/me'&&req.method==='GET')return json({authorized:await auth(req,env)});

 if(path==='/api/admin/members'&&req.method==='GET'){
  if(!await auth(req,env))return json({error:'Unauthorized'},401);
  if(!env.DISCORD_GUILD_ID||!env.DISCORD_BOT_TOKEN)return json({error:'Set DISCORD_GUILD_ID and DISCORD_BOT_TOKEN'},503);
  const query=(url.searchParams.get('q')||'').trim();if(query.length>100)return json({error:'Search too long'},400);
  try{const path='/guilds/'+encodeURIComponent(env.DISCORD_GUILD_ID)+'/members'+(query?'/search?query='+encodeURIComponent(query)+'&limit=100':'?limit=100');const members=await discordApi(env,path,'GET');return json({members:members.filter(m=>m.user&&!m.user.bot).map(m=>({id:m.user.id,username:m.user.global_name||m.user.username,nick:m.nick||null}))});}
  catch(e){return json({error:e.message+' (check Server Members Intent and bot guild membership)'},502)}
 }
 if(path==='/api/admin/invitations'&&req.method==='GET'){
  if(!await auth(req,env))return json({error:'Unauthorized'},401);
  const {results}=await env.DB.prepare('SELECT id,discord_id,steamid,nickname,status,created_at,expires_at FROM invitations ORDER BY created_at DESC LIMIT 100').all();return json({invitations:results});
 }
 if(path==='/api/admin/players'&&req.method==='GET'){if(!await auth(req,env))return json({error:'Unauthorized'},401);return json(await readPublic(env));}
 if(path==='/api/admin/logout'&&req.method==='POST'){if(req.headers.get('Origin')!==originOf(req))return json({error:'Bad origin'},403);const t=cookies(req).mp_session;if(t)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(t)).run();return json({ok:true},200,{'Set-Cookie':cookie('mp_session','',0)});}
 if(path.startsWith('/api/admin/')&&['POST','PUT','DELETE'].includes(req.method)){
  if(req.headers.get('Origin')!==originOf(req)||!req.headers.get('Content-Type')?.startsWith('application/json'))return json({error:'Bad origin or content type'},403);
  if(!await auth(req,env))return json({error:'Unauthorized'},401);

  if(path==='/api/admin/invitations'&&req.method==='POST'){
   const body=await req.json();const discordId=String(body.discord_id||'').trim(),steamid='',nickname=String(body.nickname||'').trim();
   if(!snowflake(discordId)||!nickname||nickname.length>64)return json({error:'Enter a valid Discord ID and nickname'},400);
   if(!env.DISCORD_BOT_TOKEN)return json({error:'DISCORD_BOT_TOKEN secret is missing'},503);

   const pending=await env.DB.prepare("SELECT id FROM invitations WHERE discord_id=? AND status IN ('pending','awaiting_steam') AND expires_at>?").bind(discordId,Math.floor(Date.now()/1000)).first();if(pending)return json({error:'A pending invitation already exists for this Discord account or SteamID'},409);
   const id=crypto.randomUUID(),now=Math.floor(Date.now()/1000),expires=now+DAY;
   // Check DM access before saving the invitation. Discord may reject DMs due to privacy settings.
   let dm;
   try{dm=await discordApi(env,'/users/@me/channels','POST',{recipient_id:discordId});}
   catch(e){return json({error:'Could not open Discord DM: '+e.message},502);}
   await env.DB.prepare("INSERT INTO invitations(id,discord_id,steamid,nickname,status,expires_at) VALUES(?,?,?,?,'pending',?)").bind(id,discordId,steamid,nickname,expires).run();
   const content=`**MP TEAM — Rust squad invitation**
You've been invited to join MP TEAM as **${nickname.replace(/[*_`~|<>@]/g,'')}**.
This invite expires in 24 hours. Only your Discord account can accept it.\nAfter accepting, you'll verify your Steam account on our website.`;
   try{await discordApi(env,'/channels/'+dm.id+'/messages','POST',{content,allowed_mentions:{parse:[]},components:[{type:1,components:[{type:2,style:3,label:'Accept',custom_id:'mpinv:accept:'+id},{type:2,style:4,label:'Decline',custom_id:'mpinv:decline:'+id}]}]});}
   catch(e){await env.DB.prepare("UPDATE invitations SET status='delivery_failed' WHERE id=?").bind(id).run();return json({error:'Discord could not deliver the DM: '+e.message},502);}
   return json({ok:true,id,status:'pending'},201);
  }
  const revoke=path.match(/^\/api\/admin\/invitations\/([a-f0-9-]{36})\/revoke$/);
  if(revoke&&req.method==='POST'){
   const result=await env.DB.prepare("UPDATE invitations SET status='revoked',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status IN ('pending','awaiting_steam')").bind(revoke[1]).run();return json({ok:result.meta.changes===1});
  }
  if(path==='/api/admin/players'&&req.method==='POST'){
   const body=await req.json();const steamid=String(body.steamid||'');const nickname=String(body.nickname||'').trim();if(!/^7656119\d{10}$/.test(steamid)||!nickname||nickname.length>64)return json({error:'Invalid SteamID64 or nickname'},400);
   const max=await env.DB.prepare('SELECT COALESCE(MAX(sort_order),0) AS n FROM players').first();await env.DB.prepare('INSERT INTO players(steamid,nickname,sort_order) VALUES(?,?,?)').bind(steamid,nickname,max.n+1).run();return json({ok:true});
  }
  const match=path.match(/^\/api\/admin\/players\/(\d{17})$/);
  if(match&&req.method==='PUT'){const body=await req.json();const nickname=String(body.nickname||'').trim();if(!nickname||nickname.length>64)return json({error:'Invalid nickname'},400);await env.DB.prepare('UPDATE players SET nickname=?,updated_at=CURRENT_TIMESTAMP WHERE steamid=?').bind(nickname,match[1]).run();return json({ok:true});}
  if(match&&req.method==='DELETE'){await env.DB.prepare('DELETE FROM players WHERE steamid=?').bind(match[1]).run();return json({ok:true});}
  if(path==='/api/admin/prefix'&&req.method==='PUT'){const body=await req.json();const prefix=String(body.prefix??'');if(prefix.length>20)return json({error:'Prefix too long'},400);await env.DB.prepare("INSERT INTO settings(key,value) VALUES('prefix',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(prefix).run();return json({ok:true});}
 }
 if(path==='/')return redirect('/admin');return json({error:'Not found'},404);
 }catch(e){console.error(e);if(e.message?.includes('UNIQUE constraint'))return json({error:'SteamID already exists'},409);return json({error:'Internal server error'},500);}}};
