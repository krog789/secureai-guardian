import { verifyPassword, generateSessionToken, sessionCookie, sessionExpiryMs, jsonResponse, corsJsonHeaders } from '../_lib/auth.js';

export async function onRequestOptions(){
  return new Response(null, { headers: corsJsonHeaders() });
}

export async function onRequestPost(context){
  const { request, env } = context;

  let body;
  try{ body = await request.json(); }
  catch(e){ return jsonResponse({ error: 'Invalid JSON body' }, 400); }

  const username = (body.username || '').trim().toLowerCase();
  const password = body.password || '';

  if(!username || !password){
    return jsonResponse({ error: 'Username and password are required' }, 400);
  }

  if(!env.DB){
    return jsonResponse({ error: 'Database is not connected yet. In the Cloudflare dashboard, add a D1 binding named "DB" to this project (Settings -> Functions -> D1 database bindings), then redeploy. See DEPLOY_INSTRUCTIONS.md.' }, 500);
  }

  try{
    const user = await env.DB.prepare('SELECT id, username, password_hash, salt, preferred_model FROM users WHERE username = ?').bind(username).first();
    if(!user){
      return jsonResponse({ error: 'Incorrect username or password' }, 401);
    }

    const valid = await verifyPassword(password, user.salt, user.password_hash);
    if(!valid){
      return jsonResponse({ error: 'Incorrect username or password' }, 401);
    }

    const token = generateSessionToken();
    await env.DB.prepare(
      'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(token, user.id, sessionExpiryMs()).run();

    return jsonResponse({ username: user.username, preferredModel: user.preferred_model || 'llama-3.1-8b-instant' }, 200, { 'Set-Cookie': sessionCookie(token) });
  }catch(err){
    return jsonResponse({ error: 'Database error: ' + err.message + '. Make sure schema.sql (and migration_add_model.sql if upgrading) has been run against your D1 database.' }, 500);
  }
}
