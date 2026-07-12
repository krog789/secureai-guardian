import { getUserFromSession, jsonResponse, corsJsonHeaders } from '../_lib/auth.js';

// Every user is allowed to pick from this fixed list only — never trust an
// arbitrary model string from the browser straight into the AI provider call.
const ALLOWED_MODELS = [
  'llama-3.1-8b-instant',
  'llama-3.3-70b-versatile',
  'gemma2-9b-it'
];

export async function onRequestOptions(){
  return new Response(null, { headers: corsJsonHeaders() });
}

export async function onRequestPost(context){
  const { request, env } = context;

  if(!env.DB){
    return jsonResponse({ error: 'Database is not connected yet.' }, 500);
  }

  const user = await getUserFromSession(request, env);
  if(!user){
    return jsonResponse({ error: 'Not logged in' }, 401);
  }

  let body;
  try{ body = await request.json(); }
  catch(e){ return jsonResponse({ error: 'Invalid JSON body' }, 400); }

  const model = String(body.preferredModel || '');
  if(!ALLOWED_MODELS.includes(model)){
    return jsonResponse({ error: 'Unknown model. Choose one of: ' + ALLOWED_MODELS.join(', ') }, 400);
  }

  try{
    await env.DB.prepare('UPDATE users SET preferred_model = ? WHERE id = ?').bind(model, user.id).run();
  }catch(err){
    return jsonResponse({ error: 'Database error: ' + err.message + '. Run migration_add_model.sql against your D1 database first.' }, 500);
  }

  return jsonResponse({ ok: true, preferredModel: model });
}
