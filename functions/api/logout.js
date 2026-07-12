import { parseCookies, clearSessionCookie, jsonResponse, corsJsonHeaders } from '../_lib/auth.js';

export async function onRequestOptions(){
  return new Response(null, { headers: corsJsonHeaders() });
}

export async function onRequestPost(context){
  const { request, env } = context;
  const cookies = parseCookies(request);
  const token = cookies['session'];
  if(token){
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }
  return jsonResponse({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
}
