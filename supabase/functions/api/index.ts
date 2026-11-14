// @ts-ignore The shared JavaScript module is syntax-checked separately with Node.
import backend from "../../../backend.mjs";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const allowedOrigin = Deno.env.get("APP_ORIGIN");

if (!supabaseUrl || !serviceRoleKey) {
  throw new Error("Supabase function secrets are not configured");
}

async function databaseRequest(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${supabaseUrl}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: serviceRoleKey,
      authorization: `Bearer ${serviceRoleKey}`,
      ...(init?.headers || {}),
    },
  });
}

const database = {
  async load() {
    const response = await databaseRequest("app_state?select=version,state&id=eq.1");
    if (!response.ok) throw new Error(`Could not load application state (${response.status})`);
    const rows = await response.json();
    if (!rows.length) throw new Error("Application state row is missing; apply the Supabase migrations");
    return { version: Number(rows[0].version), state: rows[0].state };
  },
  async compareAndSwap(version: number, state: unknown) {
    const response = await databaseRequest(`app_state?id=eq.1&version=eq.${version}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", prefer: "return=representation" },
      body: JSON.stringify({ version: version + 1, state }),
    });
    if (!response.ok) throw new Error(`Could not save application state (${response.status})`);
    return (await response.json()).length === 1;
  },
};

function addCors(request: Request, response: Response): Response {
  const origin = request.headers.get("origin");
  const localOrigin = origin && new URL(origin).hostname === "localhost" ? origin : null;
  const permittedOrigin = origin && (origin === allowedOrigin || localOrigin) ? origin : null;
  const headers = new Headers(response.headers);
  if (permittedOrigin) {
    headers.set("access-control-allow-origin", permittedOrigin);
    headers.set("access-control-allow-methods", "GET, POST, PATCH, DELETE, OPTIONS");
    headers.set("access-control-allow-headers", "apikey, authorization, content-type, x-sokuho-session");
    headers.set("access-control-expose-headers", "x-sokuho-session");
    headers.set("access-control-max-age", "86400");
    headers.append("vary", "Origin");
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") {
    return addCors(request, new Response(null, { status: 204 }));
  }
  const response = await backend.fetch(request, {
    DB: database,
    ADMIN_EMAIL: Deno.env.get("SOKUHO_ADMIN_EMAIL"),
    ADMIN_PASSWORD: Deno.env.get("SOKUHO_ADMIN_PASSWORD"),
  });
  return addCors(request, response);
});
