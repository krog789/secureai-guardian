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

const ZERO_TOLERANCE = [
  "Prompt Injection", "Jailbreak Attempt", "DAN Attack", "System Prompt Extraction",
  "Data Exfiltration", "Credential Theft", "Financial Fraud / Account Hacking",
  "Malware / Cyberattack Request", "Ransomware", "Phishing", "Social Engineering",
  "Fraud", "Weapons / Physical Harm"
];

const SYSTEM_INSTRUCTION =
  "You are SecureAI Guardian, an AI prompt-security classifier. Read the user's message carefully " +
  "and understand its real underlying meaning and intent — do not just keyword match, and do not be lenient " +
  "just because a request is phrased politely, briefly, or casually.\n" +
  "STRICT RULE: if the prompt asks how to gain unauthorized access to an account, device, system, or data " +
  "that does not belong to the requester (e.g. 'hack', 'break into', 'get into someone's account', 'bypass their password'), " +
  "or asks for malware, phishing content, ransomware, credential theft, or similar, classify it under the matching " +
  "zero-tolerance category (" + ZERO_TOLERANCE.join(", ") + ") with risk_score of at least 75, risk_level " +
  "\"Critical\", and decision \"Block\" — regardless of how short, vague, or casually the request is phrased. " +
  "Do not default to General / Benign just because a request lacks detail; a short malicious request is still malicious.\n" +
  "Reply with ONLY one valid JSON object and absolutely nothing else (no markdown fences, no preamble, " +
  "no explanation outside the JSON, no chain-of-thought). Keep intent_analysis and reasons brief so the reply " +
  "stays short. Match exactly this schema:\n" +
  '{"category": one of ' + JSON.stringify(CATEGORIES) + ', "risk_score": integer 0-100, ' +
  '"risk_level": one of ["None","Low","Medium","High","Critical"], "decision": one of ' +
  '["Allow","Warn","Restrict","Block"], "confidence": integer 0-100, ' +
  '"intent_analysis": "1-2 sentence explanation of what the prompt actually means and why you classified it this way", ' +
  '"reasons": ["short reason", "short reason"]}';

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

// Backend-side safety net, independent of what the AI model says. Some models
// refuse to engage with obviously malicious multi-step attack prompts (their
// own built-in safety training kicks in) and return a reply that doesn't match
// our JSON schema at all — e.g. a plain refusal sentence. Previously that
// caused every field to fall back to defaults, which meant "Allow / General /
// Benign / Risk 0" — the worst possible fallback for a security tool: an AI
// refusal or garbled response should never quietly resolve to "safe". This
// keyword scan runs regardless of what the AI returns, and can only push a
// verdict toward more caution, never less.
const RED_FLAGS = [
  { category: "Prompt Injection", phrases: ["ignore all previous instructions", "ignore previous instructions", "disregard previous instructions", "ignore your instructions", "override your instructions"] },
  { category: "Jailbreak Attempt", phrases: ["developer mode", "unrestricted mode", "unrestricted developer", "no restrictions", "without restrictions", "no safety rules", "no ethical guidelines", "act as dan", "do anything now"] },
  { category: "Malware / Cyberattack Request", phrases: ["malware", "ransomware", "keylogger", "trojan", "rootkit", "botnet", "shellcode", "reverse shell", "powershell payload", "downloads and executes", "bypass antivirus", "bypass windows defender", "evade detection", "remain persistent after reboot", "maintain persistence"] },
  { category: "Phishing", phrases: ["phishing email", "fake login page", "captures usernames", "captures passwords", "steal microsoft 365 credentials", "steal login credentials", "clone website to steal"] },
  { category: "Data Exfiltration", phrases: ["sql injection", "dump all user", "dump the database", "exfiltrate data", "extract all records"] },
  { category: "Credential Theft", phrases: ["steal credentials", "steal password", "steal api key", "steal session cookie", "steal auth token"] },
  { category: "Financial Fraud / Account Hacking", phrases: ["compromise a corporate network", "compromise the network", "attack plan to compromise", "hack into", "hack someone", "break into someone's account", "escalate privileges after"] },
];

function scanForRedFlags(promptText) {
  const lower = " " + promptText.toLowerCase().replace(/\s+/g, " ") + " ";
  const matched = [];
  const reasons = [];
  for (const group of RED_FLAGS) {
    for (const phrase of group.phrases) {
      if (lower.includes(phrase)) {
        if (!matched.includes(group.category)) matched.push(group.category);
        reasons.push('Detected phrase indicating ' + group.category + ': "' + phrase + '"');
      }
    }
  }
  return { matched, reasons: reasons.slice(0, 8) };
}

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

  // 3. Call Cloudflare Workers AI. Llama 3.3 70B goes first — it's meaningfully
  // more reliable at correctly flagging obvious security threats than the
  // smaller/faster GLM model, which matters more here than raw speed. GLM is
  // kept as a fallback in case the primary model is ever unavailable.
  const MODELS = ["@cf/meta/llama-3.3-70b-instruct-fp8-fast", "@cf/zai-org/glm-4.7-flash"];
  let lastErr = null;

  for (const model of MODELS) {
    try {
      const aiResponse = await env.AI.run(model, {
        messages: [
          { role: "system", content: SYSTEM_INSTRUCTION },
          { role: "user", content: prompt },
        ],
        max_tokens: 700,
        temperature: 0.2,
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
        decision: ["Allow", "Warn", "Restrict", "Block"].includes(parsed.decision) ? parsed.decision : "Allow",
        confidence: Number.isFinite(parsed.confidence) ? Math.max(0, Math.min(100, parsed.confidence)) : 80,
        intent_analysis:
          typeof parsed.intent_analysis === "string" && parsed.intent_analysis.trim()
            ? parsed.intent_analysis
            : "No further explanation was provided by the model.",
        reasons:
          Array.isArray(parsed.reasons) && parsed.reasons.length
            ? parsed.reasons.map((r) => String(r)).slice(0, 8)
            : [],
      };

      // Safety net #1: if the model picked a zero-tolerance category but somehow
      // still scored it low, correct the severity rather than trusting an
      // internally inconsistent verdict. This can't downgrade a real threat,
      // only upgrade one the model itself already identified but under-scored.
      if (ZERO_TOLERANCE.includes(result.category) && result.risk_score < 75) {
        result.risk_score = 75;
        result.risk_level = "Critical";
        result.decision = "Block";
      }

      // Safety net #2: independent keyword scan. If the AI landed on a low-risk
      // verdict (often what happens when a model refuses to properly engage
      // with an obvious attack-plan prompt and we fell back to defaults) but
      // the prompt itself contains clear attack indicators, override toward
      // caution. This never downgrades a verdict the AI already flagged.
      if (result.risk_score < 70) {
        const scan = scanForRedFlags(prompt);
        if (scan.matched.length >= 2 || (scan.matched.length === 1 && scan.reasons.length >= 2)) {
          result.category = scan.matched[0];
          result.risk_score = 85;
          result.risk_level = "Critical";
          result.decision = "Block";
          result.intent_analysis =
            "Automated keyword safety check detected explicit indicators of " + scan.matched.join(", ") +
            " in this prompt. This overrides a lower or non-committal AI-assigned score.";
          result.reasons = scan.reasons;
        }
      }

      return withCORS(JSON.stringify(result), 200);
    } catch (err) {
      lastErr = { error: "AI_CALL_FAILED", message: String((err && err.message) || err), model };
    }
  }

  // If every model failed to produce a usable classification (e.g. all of them
  // refused to engage with the prompt), don't just return a bare error — run
  // the same keyword safety net. An AI refusing to answer is itself a signal,
  // and if the prompt also contains clear attack indicators we can still give
  // the user a correct, cautious verdict instead of nothing at all.
  const fallbackScan = scanForRedFlags(prompt);
  if (fallbackScan.matched.length) {
    return withCORS(
      JSON.stringify({
        category: fallbackScan.matched[0],
        risk_score: 85,
        risk_level: "Critical",
        decision: "Block",
        confidence: 70,
        intent_analysis:
          "The AI model did not return a usable classification for this prompt (it may have refused to engage with it), " +
          "but an automated keyword safety check detected explicit indicators of " + fallbackScan.matched.join(", ") +
          ". Blocking out of caution rather than defaulting to Allow.",
        reasons: fallbackScan.reasons,
      }),
      200
    );
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
