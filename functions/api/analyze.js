// This file runs on Cloudflare's servers, NOT in the visitor's browser.
// It calls Cloudflare Workers AI directly (no external API key needed) and
// verifies the visitor is a real signed-in Supabase user before running AI.

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
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };
}

export async function onRequestOptions(){
  return new Response(null, { headers: corsHeaders() });
}

/* Verifies the visitor's Supabase access token by asking Supabase itself
   whether it's valid — no JWT library or secret needed on our side. */
async function verifySupabaseUser(request, env){
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if(!token || !env.SUPABASE_URL || !env.SUPABASE_ANON_KEY) return null;

  try{
    const res = await fetch(env.SUPABASE_URL.replace(/\/+$/,'') + '/auth/v1/user', {
      headers: {
        'apikey': env.SUPABASE_ANON_KEY,
        'Authorization': 'Bearer ' + token
      }
    });
    if(!res.ok) return null;
    return await res.json();
  }catch(e){
    return null;
  }
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

  // Require a real, verified Supabase session so the free Workers AI quota
  // can't be spammed by anonymous internet traffic.
  const user = await verifySupabaseUser(request, env);
  if(!user){
    return new Response(JSON.stringify({ error: 'Not signed in, or Supabase is not configured on the server yet (SUPABASE_URL / SUPABASE_ANON_KEY env vars).' }), { status: 401, headers: corsHeaders() });
  }

  if(!env.AI){
    return new Response(JSON.stringify({ error: 'Workers AI binding is missing. In the Cloudflare dashboard, go to your project -> Settings -> Functions -> Bindings, and add a Workers AI binding named "AI".' }), { status: 500, headers: corsHeaders() });
  }

  const systemPrompt = 'You are SecureAI Guardian, an AI prompt-security classifier. Read the user\'s message carefully and understand its real underlying meaning and intent — do not just pattern-match keywords. ' +
    'Reply with ONLY one valid JSON object and absolutely nothing else (no markdown fences, no preamble), matching exactly this schema:\n' +
    '{"category": one of ' + JSON.stringify(CATEGORIES) + ', "risk_score": integer 0-100, "risk_level": one of ["None","Low","Medium","High","Critical"], "decision": one of ["Allow","Warn","Restrict","Block"], "confidence": integer 0-100, "intent_analysis": "2-3 sentence explanation of what the prompt actually means and why", "reasons": ["short reason", "short reason"]}';

  try{
    const aiResponse = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: 'Classify this prompt:\n\n"""' + prompt + '"""' }
      ],
      temperature: 0.1
    });

    const raw = (aiResponse && aiResponse.response) ? aiResponse.response : '';
    const match = raw.match(/\{[\s\S]*\}/);
    if(!match){
      return new Response(JSON.stringify({ error: 'Workers AI did not return valid JSON', raw }), { status: 502, headers: corsHeaders() });
    }

    let parsed;
    try{ parsed = JSON.parse(match[0]); }
    catch(e){ return new Response(JSON.stringify({ error: 'Could not parse AI JSON: ' + match[0].slice(0,200) }), { status: 502, headers: corsHeaders() }); }

    return new Response(JSON.stringify(parsed), { status: 200, headers: corsHeaders() });
  }catch(err){
    return new Response(JSON.stringify({ error: 'Workers AI error: ' + err.message }), { status: 500, headers: corsHeaders() });
  }
}
