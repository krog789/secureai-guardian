// This file lives at /functions/api/analyze.js
// Cloudflare Pages automatically turns this into a live endpoint at:  https://YOURSITE.pages.dev/api/analyze
// It uses Cloudflare Workers AI — free, built into your Cloudflare account, no separate API key needed.
// You DO need to turn on the "AI" binding in your Pages project settings — see DEPLOY_README.md.

const CATEGORIES = [
  "Prompt Injection","Jailbreak Attempt","DAN Attack","System Prompt Extraction",
  "Data Exfiltration","Credential Theft","Sensitive Data Request",
  "Financial Fraud / Account Hacking","Malware / Cyberattack Request","Ransomware",
  "Phishing","Social Engineering","Fraud","Cyber Abuse","Weapons / Physical Harm",
  "Policy Violation","General / Benign"
];

const SYSTEM_INSTRUCTION =
  'You are SecureAI Guardian, an AI prompt-security classifier. Read the user\'s message carefully and understand its real underlying meaning and intent — do not just pattern-match keywords. ' +
  'Reply with ONLY one valid JSON object and absolutely nothing else (no markdown fences, no preamble, no explanation outside the JSON), matching exactly this schema:\n' +
  '{"category": one of ' + JSON.stringify(CATEGORIES) + ', "risk_score": integer 0-100, "risk_level": one of ["None","Low","Medium","High","Critical"], "decision": one of ["Allow","Warn","Restrict","Block"], "confidence": integer 0-100, "intent_analysis": "2-3 sentence explanation of what the prompt actually means and why you classified it this way", "reasons": ["short reason", "short reason"]}';

function withCORS(body, status) {
  return new Response(body, {
    status: status || 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}

export async function onRequestOptions() {
  return withCORS(null, 204);
}

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.AI) {
    return withCORS(JSON.stringify({
      error: "Workers AI binding is not configured. In Cloudflare Pages: Settings → Functions → AI bindings → add a binding named 'AI'. Then redeploy."
    }), 500);
  }

  let promptText;
  try {
    const body = await request.json();
    promptText = (body.prompt || "").toString().trim();
  } catch (e) {
    return withCORS(JSON.stringify({ error: "Invalid request body — expected JSON with a 'prompt' field." }), 400);
  }

  if (!promptText) {
    return withCORS(JSON.stringify({ error: "No prompt provided." }), 400);
  }
  if (promptText.length > 5000) {
    promptText = promptText.slice(0, 5000);
  }

  try {
    const aiResponse = await env.AI.run("@cf/meta/llama-3.2-3b-instruct", {
      messages: [
        { role: "system", content: SYSTEM_INSTRUCTION },
        { role: "user", content: 'Classify this prompt:\n\n"""' + promptText + '"""' }
      ],
      max_tokens: 300
    });

    // Workers AI usually returns { response: "text" }, but depending on the model
    // it can occasionally return the parsed object directly, or nest it differently.
    // Normalize whatever comes back into a plain string before regex-matching JSON out of it.
    let raw = aiResponse && aiResponse.response;
    if (raw && typeof raw === "object") {
      // Model already returned structured data — use it directly if it looks right
      if (raw.category || raw.risk_score !== undefined || raw.decision) {
        raw = JSON.stringify(raw);
      } else {
        raw = JSON.stringify(raw);
      }
    }
    if (typeof raw !== "string") {
      raw = aiResponse ? JSON.stringify(aiResponse) : "";
    }

    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) {
      return withCORS(JSON.stringify({ error: "AI model did not return valid JSON.", raw }), 502);
    }

    let parsed;
    try {
      parsed = JSON.parse(match[0]);
    } catch (e) {
      return withCORS(JSON.stringify({ error: "Could not parse AI model's JSON output.", raw }), 502);
    }

    // Basic validation/clamping so a malformed model response can't crash the frontend
    if (!CATEGORIES.includes(parsed.category)) parsed.category = "General / Benign";
    parsed.risk_score = Math.max(0, Math.min(100, parseInt(parsed.risk_score, 10) || 0));
    parsed.confidence = Math.max(0, Math.min(100, parseInt(parsed.confidence, 10) || 50));
    if (!["None","Low","Medium","High","Critical"].includes(parsed.risk_level)) parsed.risk_level = "Low";
    if (!["Allow","Warn","Restrict","Block"].includes(parsed.decision)) parsed.decision = "Allow";
    if (!parsed.intent_analysis) parsed.intent_analysis = "AI-based classification completed.";
    if (!Array.isArray(parsed.reasons)) parsed.reasons = [];

    return withCORS(JSON.stringify(parsed), 200);
  } catch (err) {
    return withCORS(JSON.stringify({ error: "AI request failed: " + (err && err.message ? err.message : String(err)) }), 500);
  }
}
