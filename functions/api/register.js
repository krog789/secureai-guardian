import { hashPassword, generateSessionToken, sessionCookie, sessionExpiryMs, jsonResponse, corsJsonHeaders } from '../_lib/auth.js';

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

  if(!/^[a-z0-9_.-]{3,32}$/.test(username)){
    return jsonResponse({ error: 'Username must be 3-32 characters (letters, numbers, . _ - only)' }, 400);
  }
  if(password.length < 6){
    return jsonResponse({ error: 'Password must be at least 6 characters' }, 400);
  }

  if(!env.DB){
    return jsonResponse({ error: 'Database is not connected yet. In the Cloudflare dashboard, add a D1 binding named "DB" to this project (Settings -> Functions -> D1 database bindings), then redeploy. See DEPLOY_INSTRUCTIONS.md.' }, 500);
  }

  try{
    const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
    if(existing){
      return jsonResponse({ error: 'That username is already taken' }, 409);
    }

    const { hash, salt } = await hashPassword(password);
    const result = await env.DB.prepare(
      'INSERT INTO users (username, password_hash, salt, created_at, preferred_model) VALUES (?, ?, ?, ?, ?)'
    ).bind(username, hash, salt, new Date().toISOString(), 'llama-3.1-8b-instant').run();

    const userId = result.meta.last_row_id;
    const token = generateSessionToken();
    await env.DB.prepare(
      'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(token, userId, sessionExpiryMs()).run();

    return jsonResponse({ username, preferredModel: 'llama-3.1-8b-instant' }, 200, { 'Set-Cookie': sessionCookie(token) });
  }catch(err){
    return jsonResponse({ error: 'Database error: ' + err.message + '. Make sure schema.sql (and migration_add_model.sql if upgrading) has been run against your D1 database.' }, 500);
  }
}
