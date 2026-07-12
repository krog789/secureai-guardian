// Sends every homepage "Contact" form submission straight to your inbox.
// Uses Resend (https://resend.com) — a free email API. See DEPLOY_INSTRUCTIONS.md
// for how to get a RESEND_API_KEY.

const OWNER_EMAIL = 'sohamdeep7896@gmail.com';

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

function escapeHtml(str){
  return String(str || '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

export async function onRequestPost(context){
  const { request, env } = context;

  let body;
  try{ body = await request.json(); }
  catch(e){ return new Response(JSON.stringify({ error: 'Invalid JSON body' }), { status: 400, headers: corsHeaders() }); }

  const name = String(body.name || '').trim().slice(0, 200);
  const email = String(body.email || '').trim().slice(0, 200);
  const organization = String(body.organization || '').trim().slice(0, 200);
  const message = String(body.message || '').trim().slice(0, 5000);

  if(!name || !email || !message){
    return new Response(JSON.stringify({ error: 'Name, email, and message are required' }), { status: 400, headers: corsHeaders() });
  }
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){
    return new Response(JSON.stringify({ error: 'Please enter a valid email address' }), { status: 400, headers: corsHeaders() });
  }

  if(!env.RESEND_API_KEY){
    return new Response(JSON.stringify({ error: 'Server is missing RESEND_API_KEY. Set it with: wrangler pages secret put RESEND_API_KEY (see DEPLOY_INSTRUCTIONS.md)' }), { status: 500, headers: corsHeaders() });
  }

  const html = `
    <h2>New inquiry from SecureAI Guardian</h2>
    <p><b>Name:</b> ${escapeHtml(name)}</p>
    <p><b>Email:</b> ${escapeHtml(email)}</p>
    <p><b>Organization:</b> ${escapeHtml(organization) || '—'}</p>
    <p><b>Message:</b></p>
    <p style="white-space:pre-wrap;">${escapeHtml(message)}</p>
  `;

  try{
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + env.RESEND_API_KEY
      },
      body: JSON.stringify({
        from: 'SecureAI Guardian <onboarding@resend.dev>',
        to: [OWNER_EMAIL],
        reply_to: email,
        subject: 'New contact form inquiry from ' + name,
        html
      })
    });

    if(!res.ok){
      const errText = await res.text().catch(()=> '');
      return new Response(JSON.stringify({ error: 'Email provider error (HTTP ' + res.status + '): ' + errText.slice(0, 300) }), { status: 502, headers: corsHeaders() });
    }

    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: corsHeaders() });
  }catch(err){
    return new Response(JSON.stringify({ error: 'Server error: ' + err.message }), { status: 500, headers: corsHeaders() });
  }
}
