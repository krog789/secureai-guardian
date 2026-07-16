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

  // 3. Call Cloudflare Workers AI. Try the primary model first; if it fails
  // (e.g. deprecated, temporarily overloaded), automatically retry with a
  // backup model so one model going away doesn't take the whole feature down.
  const MODELS = ["@cf/zai-org/glm-4.7-flash", "@cf/meta/llama-3.3-70b-instruct-fp8-fast"];
  let lastErr = null;

  for (const model of MODELS) {
    try {
      const aiResponse = await env.AI.run(model, {
        messages: [
          { role: "system", content: SYSTEM_INSTRUCTION },
          { role: "user", content: prompt },
        ],
        max_tokens: 900,
      });

      // Different Workers AI models shape their reply differently: some return
      // a plain string in `response`, some return an already-parsed object
      // (e.g. when the model natively supports JSON mode), and some use
      // `result` instead of `response`. Handle all three instead of assuming
      // a string, which previously turned real objects into the literal text
      // "[object Object]" via `+ ""`.
      const respField = aiResponse && aiResponse.response;
      let raw;
      if (typeof respField === "string") {
        raw = respField;
      } else if (respField && typeof respField === "object") {
        raw = JSON.stringify(respField);
      } else if (typeof (aiResponse && aiResponse.result) === "string") {
        raw = aiResponse.result;
      } else if (aiResponse && aiResponse.result && typeof aiResponse.result === "object") {
        raw = JSON.stringify(aiResponse.result);
      } else {
        raw = JSON.stringify(aiResponse || {});
      }

      const parsed = extractJSON(raw);

      if (!parsed) {
        lastErr = { error: "MODEL_PARSE_ERROR", message: "The model responded but not with valid JSON.", raw, model };
        continue;
      }

      const result = {
        category: CATEGORIES.includes(parsed.category) ? parsed.category : "General / Benign",
        risk_score: Number.isFinite(parsed.risk_score) ? Math.max(0, Math.min(100, parsed.risk_score)) : 0,
        risk_level: ["None", "Low", "Medium", "High", "Critical"].includes(parsed.risk_level) ? parsed.risk_level : "None",
        decision: ["Allow", "Flag", "Block"].includes(parsed.decision) ? parsed.decision : "Allow",
        reasoning: typeof parsed.reasoning === "string" && parsed.reasoning.trim() ? parsed.reasoning : "No further explanation was provided by the model.",
      };

      return withCORS(JSON.stringify(result), 200);
    } catch (err) {
      lastErr = { error: "AI_CALL_FAILED", message: String((err && err.message) || err), model };
    }
  }

  return withCORS(JSON.stringify(lastErr || { error: "AI_CALL_FAILED", message: "All models failed." }), 500);
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
// Also repairs JSON that got cut off mid-field (e.g. hit the token limit
// before the model finished writing), so a truncated "reasoning" sentence
// at the end doesn't throw away an otherwise-complete, usable verdict.
function extractJSON(text) {
  if (!text) return null;
  let cleaned = text.trim().replace(/```json/gi, "").replace(/```/g, "").trim();

  try {
    return JSON.parse(cleaned);
  } catch (_) {
    // fall through to repair attempts below
  }

  const start = cleaned.indexOf("{");
  if (start === -1) return null;
  let candidate = cleaned.slice(start);

  try {
    return JSON.parse(candidate);
  } catch (_) {
    // fall through
  }

  const repaired = repairTruncatedJSON(candidate);
  if (repaired) {
    try {
      return JSON.parse(repaired);
    } catch (_) {
      return null;
    }
  }
  return null;
}

function repairTruncatedJSON(str) {
  let s = str;

  // If we're mid-string (odd number of unescaped quotes), close the string.
  const quoteCount = (s.match(/(?<!\\)"/g) || []).length;
  if (quoteCount % 2 !== 0) s += '"';

  // Drop a trailing comma / colon / partial key left dangling by truncation.
  s = s.replace(/,\s*$/, "").replace(/:\s*$/, "").replace(/,\s*"[^"]*$/, "");

  // Balance brackets/braces.
  const opens = (s.match(/\{/g) || []).length;
  const closes = (s.match(/\}/g) || []).length;
  const opensArr = (s.match(/\[/g) || []).length;
  const closesArr = (s.match(/\]/g) || []).length;

  s += "]".repeat(Math.max(0, opensArr - closesArr));
  s += "}".repeat(Math.max(0, opens - closes));

  return s;
}
