import { getUserFromSession, jsonResponse, corsJsonHeaders } from '../_lib/auth.js';

export async function onRequestOptions(){
  return new Response(null, { headers: corsJsonHeaders() });
}

export async function onRequestGet(context){
  const { request, env } = context;
  if(!env.DB){
    return jsonResponse({ error: 'Database is not connected yet.' }, 500);
  }
  const user = await getUserFromSession(request, env);
  if(!user){
    return jsonResponse({ error: 'Not logged in' }, 401);
  }
  let preferredModel = 'llama-3.1-8b-instant';
  try{
    const row = await env.DB.prepare('SELECT preferred_model FROM users WHERE id = ?').bind(user.id).first();
    if(row && row.preferred_model) preferredModel = row.preferred_model;
  }catch(e){ /* column may not exist yet if migration hasn't run — fall back to default */ }
  return jsonResponse({ username: user.username, preferredModel });
}
