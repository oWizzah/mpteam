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
export default {async fetch(req,env){try{
 const url=new URL(req.url),path=url.pathname;
 if(req.method==='OPTIONS'&&path==='/api/public'){return new Response(null,{status:204,headers:{...cors(req,env),'Access-Control-Allow-Methods':'GET, OPTIONS','Access-Control-Allow-Headers':'Content-Type','Access-Control-Max-Age':'86400'}});}
 if(path==='/api/public'&&req.method==='GET')return json(await readPublic(env),200,{...cors(req,env),'Cache-Control':'public, max-age=30'});
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
 if(path==='/api/admin/players'&&req.method==='GET'){if(!await auth(req,env))return json({error:'Unauthorized'},401);return json(await readPublic(env));}
 if(path==='/api/admin/logout'&&req.method==='POST'){if(req.headers.get('Origin')!==originOf(req))return json({error:'Bad origin'},403);const t=cookies(req).mp_session;if(t)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(t)).run();return json({ok:true},200,{'Set-Cookie':cookie('mp_session','',0)});}
 if(path.startsWith('/api/admin/')&&['POST','PUT','DELETE'].includes(req.method)){
  if(req.headers.get('Origin')!==originOf(req)||!req.headers.get('Content-Type')?.startsWith('application/json'))return json({error:'Bad origin or content type'},403);
  if(!await auth(req,env))return json({error:'Unauthorized'},401);
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
