import { getUserFromSession, jsonResponse, corsJsonHeaders } from '../_lib/auth.js';

export async function onRequestOptions(){
  return new Response(null, { headers: corsJsonHeaders() });
}

export async function onRequestGet(context){
  const { request, env } = context;
  const user = await getUserFromSession(request, env);
  if(!user) return jsonResponse({ error: 'Not logged in' }, 401);

  const { results } = await env.DB.prepare(
    'SELECT id, text, timestamp, risk_score, risk_level, decision, category, confidence, reasons, behavioral, intent_analysis FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 500'
  ).bind(user.id).all();

  const history = (results || []).map(r => ({
    id: r.id,
    text: r.text,
    timestamp: r.timestamp,
    riskScore: r.risk_score,
    riskLevel: r.risk_level,
    decision: r.decision,
    category: r.category,
    confidence: r.confidence,
    reasons: r.reasons ? JSON.parse(r.reasons) : [],
    behavioral: r.behavioral ? JSON.parse(r.behavioral) : [],
    intentAnalysis: r.intent_analysis
  }));

  return jsonResponse({ history });
}

export async function onRequestPost(context){
  const { request, env } = context;
  const user = await getUserFromSession(request, env);
  if(!user) return jsonResponse({ error: 'Not logged in' }, 401);

  let body;
  try{ body = await request.json(); }
  catch(e){ return jsonResponse({ error: 'Invalid JSON body' }, 400); }

  await env.DB.prepare(
    `INSERT INTO audit_log (user_id, text, timestamp, risk_score, risk_level, decision, category, confidence, reasons, behavioral, intent_analysis)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    user.id,
    body.text || '',
    body.timestamp || new Date().toISOString(),
    body.riskScore || 0,
    body.riskLevel || 'None',
    body.decision || 'Allow',
    body.category || 'General / Benign',
    body.confidence || 0,
    JSON.stringify(body.reasons || []),
    JSON.stringify(body.behavioral || []),
    body.intentAnalysis || ''
  ).run();

  return jsonResponse({ ok: true });
}

export async function onRequestDelete(context){
  const { request, env } = context;
  const user = await getUserFromSession(request, env);
  if(!user) return jsonResponse({ error: 'Not logged in' }, 401);

  await env.DB.prepare('DELETE FROM audit_log WHERE user_id = ?').bind(user.id).run();
  return jsonResponse({ ok: true });
}
