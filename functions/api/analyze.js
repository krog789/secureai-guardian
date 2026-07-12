// This file runs on Cloudflare's servers, NOT in the visitor's browser.
// It keeps your secret API key hidden while letting every visitor use AI analysis.

import { getUserFromSession } from '../_lib/auth.js';

const DEFAULT_MODEL = 'llama-3.1-8b-instant';
const ALLOWED_MODELS = [
  'llama-3.1-8b-instant',
  'llama-3.3-70b-versatile',
  'gemma2-9b-it'
];

const CATEGORIES = [
  "Prompt Injection","Jailbreak Attempt","DAN Attack","System Prompt Extraction",
  "Data Exfiltration","Credential Theft","Sensitive Data Request",
  "Financial Fraud / Account Hacking","Malware / Cyberattack Request","Ransomware",
  "Phishing","Social Engineering","Fraud","Cyber Abuse","Weapons / Physical Harm",
  "Policy Violation","General / Benign"
];

function corsHeaders(){
  return {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
}

export async function onRequestOptions(){
  return new Response(null, { headers: corsHeaders() });
}

export async function onRequestPost(context){
  const { request, env } = context;

  let body;
  try{
    body = await request.json();
  }catch(e){
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), { status: 400, headers: corsHeaders() });
  }

  const prompt = (body && body.prompt ? String(body.prompt) : '').slice(0, 5000);
  if(!prompt.trim()){
    return new Response(JSON.stringify({ error: 'Prompt is required' }), { status: 400, headers: corsHeaders() });
  }

  if(!env.GROQ_API_KEY){
    return new Response(JSON.stringify({ error: 'Server is missing GROQ_API_KEY. Set it with: wrangler pages secret put GROQ_API_KEY' }), { status: 500, headers: corsHeaders() });
  }

  // Each logged-in user gets analysis run through their own chosen model —
  // falls back to the default model for logged-out/demo requests or if the
  // database/column isn't set up yet.
  let model = DEFAULT_MODEL;
  try{
    if(env.DB){
      const user = await getUserFromSession(request, env);
      if(user){
        const row = await env.DB.prepare('SELECT preferred_model FROM users WHERE id = ?').bind(user.id).first();
        if(row && row.preferred_model && ALLOWED_MODELS.includes(row.preferred_model)){
          model = row.preferred_model;
        }
      }
    }
  }catch(e){ /* fall back to default model on any lookup issue */ }

  const systemPrompt = 'You are SecureAI Guardian, an AI prompt-security classifier. Read the user\'s message carefully and understand its real underlying meaning and intent — do not just pattern-match keywords. ' +
    'Reply with ONLY one valid JSON object and absolutely nothing else (no markdown fences, no preamble), matching exactly this schema:\n' +
    '{"category": one of ' + JSON.stringify(CATEGORIES) + ', "risk_score": integer 0-100, "risk_level": one of ["None","Low","Medium","High","Critical"], "decision": one of ["Allow","Warn","Restrict","Block"], "confidence": integer 0-100, "intent_analysis": "2-3 sentence explanation of what the prompt actually means and why", "reasons": ["short reason", "short reason"]}';

  try{
    const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + env.GROQ_API_KEY
      },
      body: JSON.stringify({
        model: model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: 'Classify this prompt:\n\n"""' + prompt + '"""' }
        ],
        temperature: 0.1,
        response_format: { type: 'json_object' }
      })
    });

    if(!groqRes.ok){
      const errText = await groqRes.text().catch(()=> '');
      return new Response(JSON.stringify({ error: 'AI provider error (HTTP ' + groqRes.status + '): ' + errText.slice(0, 300) }), { status: 502, headers: corsHeaders() });
    }

    const data = await groqRes.json();
    const raw = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
    const match = raw.match(/\{[\s\S]*\}/);
    if(!match){
      return new Response(JSON.stringify({ error: 'AI did not return valid JSON', raw }), { status: 502, headers: corsHeaders() });
    }

    let parsed;
    try{ parsed = JSON.parse(match[0]); }
    catch(e){ return new Response(JSON.stringify({ error: 'Could not parse AI JSON: ' + match[0].slice(0,200) }), { status: 502, headers: corsHeaders() }); }

    parsed.model_used = model;
    return new Response(JSON.stringify(parsed), { status: 200, headers: corsHeaders() });
  }catch(err){
    return new Response(JSON.stringify({ error: 'Server error: ' + err.message }), { status: 500, headers: corsHeaders() });
  }
}
