// This file lives at /functions/api/analyze.js in your repo.
// Cloudflare Pages automatically turns this into a live endpoint at:
//   https://YOURSITE.pages.dev/api/analyze
// It uses Cloudflare Workers AI — free tier included with every Cloudflare
// account, no separate API key needed. You DO still need to turn on the
// "Workers AI" binding for this Pages project (see the steps below the code).

const CATEGORIES = [
  "Prompt Injection", "Jailbreak Attempt", "DAN Attack", "System Prompt Extraction",
  "Data Exfiltration", "Credential Theft", "Sensitive Data Request",
  "Financial Fraud / Account Hacking", "Malware / Cyberattack Request", "Ransomware",
  "Phishing", "Social Engineering", "Fraud", "Cyber Abuse", "Weapons / Physical Harm",
  "Policy Violation", "General / Benign"
];

const SYSTEM_INSTRUCTION =
  "You are SecureAI Guardian, an AI prompt-security classifier. Read the user's message carefully " +
  "and understand its real underlying meaning and intent — do not just keyword match.\n" +
  "Reply with ONLY one valid JSON object and absolutely nothing else (no markdown fences, no preamble, " +
  "no explanation outside the JSON), matching exactly this schema:\n" +
  '{"category": one of ' + JSON.stringify(CATEGORIES) + ', "risk_score": integer 0-100, ' +
  '"risk_level": one of ["None","Low","Medium","High","Critical"], "decision": one of ' +
  '["Allow","Flag","Block"], "reasoning": a short 1-2 sentence explanation}';

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function withCORS(body, status) {
  return new Response(body, {
    status: status || 200,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS,
    },
  });
}

// Handles the CORS preflight request browsers send before a POST
export async function onRequestOptions() {
  return withCORS(null, 204);
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. Make sure the Workers AI binding is actually turned on for this project
  if (!env.AI) {
    return withCORS(
      JSON.stringify({
        error: "AI_BINDING_MISSING",
        message:
          "The Workers AI binding is not configured for this Pages project. " +
          "Go to Cloudflare dashboard → Workers & Pages → your project → Settings → " +
          "Functions → Bindings → Add binding → type 'AI', name it 'AI' → Save, then redeploy.",
      }),
      500
    );
  }

  // 2. Parse the incoming prompt
  let prompt;
  try {
    const body = await request.json();
    prompt = (body && body.prompt) || "";
  } catch (err) {
    return withCORS(JSON.stringify({ error: "BAD_REQUEST", message: "Body must be JSON: {\"prompt\": \"...\"}" }), 400);
  }

  if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
    return withCORS(JSON.stringify({ error: "EMPTY_PROMPT", message: "No prompt text was provided." }), 400);
  }

  // 3. Call Cloudflare Workers AI
  try {
    const aiResponse = await env.AI.run("@cf/meta/llama-3.1-8b-instruct", {
      messages: [
        { role: "system", content: SYSTEM_INSTRUCTION },
        { role: "user", content: prompt },
      ],
      max_tokens: 400,
    });

    const raw = (aiResponse && (aiResponse.response || aiResponse.result || "")) + "";
    const parsed = extractJSON(raw);

    if (!parsed) {
      return withCORS(
        JSON.stringify({
          error: "MODEL_PARSE_ERROR",
          message: "The model responded but not with valid JSON.",
          raw,
        }),
        502
      );
    }

    return withCORS(JSON.stringify(parsed), 200);
  } catch (err) {
    return withCORS(
      JSON.stringify({ error: "AI_CALL_FAILED", message: String((err && err.message) || err) }),
      500
    );
  }
}

// Optional: reject GET with a friendly message instead of Cloudflare's default 405 page
export async function onRequestGet() {
  return withCORS(
    JSON.stringify({ message: "This endpoint only accepts POST requests with a JSON body: {\"prompt\": \"...\"}" }),
    405
  );
}

// Pulls the first valid JSON object out of the model's raw text output,
// even if it wrapped it in markdown fences or added stray words around it.
function extractJSON(text) {
  if (!text) return null;
  let cleaned = text.trim().replace(/```json/gi, "").replace(/```/g, "").trim();
  try {
    return JSON.parse(cleaned);
  } catch (_) {
    const match = cleaned.match(/\{[\s\S]*\}/);
    if (match) {
      try {
        return JSON.parse(match[0]);
      } catch (_) {
        return null;
      }
    }
    return null;
  }
}
