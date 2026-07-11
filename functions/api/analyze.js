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
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}

export async function onRequestOptions() {
  return withCORS(null, 204);
}

export async function onRequestGet(context) {
  const { env } = context;
  return withCORS(JSON.stringify({
    status: env.AI ? "ok" : "missing_binding",
    message: env.AI
      ? "Cloud AI endpoint is reachable and the AI binding is configured."
      : "Endpoint is reachable, but the 'AI' binding is not configured in Pages Settings → Functions → Bindings.",
    model: "@cf/zai-org/glm-4.7-flash"
  }), 200);
}

// Tries every common shape Workers AI model responses come back in, in
// order, and returns the first non-empty text found. Different model
// families on Cloudflare's catalog place the generated text in different
// fields (plain .response, OpenAI-style .choices[0].message.content,
// .result, or occasionally the raw string itself) - this covers all of
// them instead of assuming just one.
function extractText(aiResponse) {
  if (!aiResponse) return "";
  if (typeof aiResponse === "string") return aiResponse;

  const candidates = [
    aiResponse.response,
    aiResponse.result,
    aiResponse.output_text,
    aiResponse.text,
    aiResponse?.choices?.[0]?.message?.content,
    aiResponse?.choices?.[0]?.text,
    aiResponse?.result?.response,
    Array.isArray(aiResponse?.content) ? aiResponse.content.map(c => c?.text || "").join("") : null,
  ];

  for (const c of candidates) {
    if (typeof c === "string" && c.trim().length > 0) return c;
  }
  return "";
}

// Extracts the first complete {...} JSON object from a string, tolerant of
// extra text/markdown fences before or after it.
function extractJson(text) {
  let cleaned = text.trim();
  if (cleaned.startsWith("```")) {
    cleaned = cleaned.replace(/^```(json)?/i, "").replace(/```$/, "").trim();
  }
  const first = cleaned.indexOf("{");
  const last = cleaned.lastIndexOf("}");
  if (first === -1 || last === -1 || last <= first) return null;
  try {
    return JSON.parse(cleaned.slice(first, last + 1));
  } catch (e) {
    return null;
  }
}

function clampResult(parsed) {
  if (!CATEGORIES.includes(parsed.category)) parsed.category = "General / Benign";
  parsed.risk_score = Math.max(0, Math.min(100, parseInt(parsed.risk_score, 10) || 0));
  parsed.confidence = Math.max(0, Math.min(100, parseInt(parsed.confidence, 10) || 50));
  if (!["None","Low","Medium","High","Critical"].includes(parsed.risk_level)) parsed.risk_level = "Low";
  if (!["Allow","Warn","Restrict","Block"].includes(parsed.decision)) parsed.decision = "Allow";
  if (!parsed.intent_analysis) parsed.intent_analysis = "AI-based classification completed.";
  if (!Array.isArray(parsed.reasons)) parsed.reasons = [];
  return parsed;
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

  const messages = [
    { role: "system", content: SYSTEM_INSTRUCTION },
    { role: "user", content: 'Classify this prompt:\n\n"""' + promptText + '"""' }
  ];

  // Try the messages-based call first, then fall back to a plain prompt-
  // based call if the model/binding doesn't like the messages format for
  // some reason - this removes another category of silent failure.
  let aiResponse;
  let callError = null;
  try {
    aiResponse = await env.AI.run("@cf/zai-org/glm-4.7-flash", { messages, max_tokens: 512 });
  } catch (err) {
    callError = err;
  }

  let raw = callError ? "" : extractText(aiResponse);

  if (!raw) {
    try {
      const flatPrompt = SYSTEM_INSTRUCTION + '\n\nClassify this prompt:\n\n"""' + promptText + '"""';
      aiResponse = await env.AI.run("@cf/zai-org/glm-4.7-flash", { prompt: flatPrompt, max_tokens: 512 });
      raw = extractText(aiResponse);
      callError = null;
    } catch (err) {
      callError = err;
    }
  }

  if (callError) {
    return withCORS(JSON.stringify({
      error: "AI request failed: " + (callError.message || String(callError))
    }), 500);
  }

  let parsed = raw ? extractJson(raw) : null;

  if (!parsed) {
    // Graceful degradation: rather than a hard error the user has to
    // interpret, return a valid, clearly-labeled fallback result so the
    // page always shows something usable, plus full diagnostics for us to
    // read if it keeps happening.
    return withCORS(JSON.stringify({
      category: "General / Benign",
      risk_score: 0,
      risk_level: "Low",
      decision: "Allow",
      confidence: 0,
      intent_analysis: "Cloud AI did not return a parseable classification for this prompt. This result is a safe placeholder, not a real analysis - falling back to the rule-based engine is recommended until this is resolved.",
      reasons: ["cloud_ai_parse_failed"],
      _debug: { raw_text_found: raw, full_ai_response_object: aiResponse }
    }), 200);
  }

  return withCORS(JSON.stringify(clampResult(parsed)), 200);
}
