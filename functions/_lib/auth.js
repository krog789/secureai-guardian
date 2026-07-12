// Shared auth helpers used by every /api/* function.
// Runs on Cloudflare's servers — never sent to the browser.

function bytesToHex(bytes){
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex){
  const bytes = new Uint8Array(hex.length / 2);
  for(let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

export async function hashPassword(password, existingSaltHex){
  const enc = new TextEncoder();
  const salt = existingSaltHex ? hexToBytes(existingSaltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}

export async function verifyPassword(password, saltHex, expectedHashHex){
  const { hash } = await hashPassword(password, saltHex);
  return hash === expectedHashHex;
}

export function generateSessionToken(){
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

export function parseCookies(request){
  const header = request.headers.get('Cookie') || '';
  const cookies = {};
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if(idx > -1){
      cookies[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
    }
  });
  return cookies;
}

export async function getUserFromSession(request, env){
  const cookies = parseCookies(request);
  const token = cookies['session'];
  if(!token) return null;
  const row = await env.DB.prepare(
    'SELECT s.user_id as id, u.username as username, s.expires_at as expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?'
  ).bind(token).first();
  if(!row) return null;
  if(row.expires_at < Date.now()){
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  return { id: row.id, username: row.username };
}

const THIRTY_DAYS_SECONDS = 60 * 60 * 24 * 30;
const THIRTY_DAYS_MS = THIRTY_DAYS_SECONDS * 1000;

export function sessionCookie(token){
  return `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${THIRTY_DAYS_SECONDS}`;
}

export function clearSessionCookie(){
  return `session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

export function sessionExpiryMs(){
  return Date.now() + THIRTY_DAYS_MS;
}

export function corsJsonHeaders(extra){
  return Object.assign({
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true'
  }, extra || {});
}

export function jsonResponse(obj, status, extraHeaders){
  return new Response(JSON.stringify(obj), { status: status || 200, headers: corsJsonHeaders(extraHeaders) });
}
