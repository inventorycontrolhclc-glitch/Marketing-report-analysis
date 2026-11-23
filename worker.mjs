const API = "https://api.zetpy.com/api/";
const PROJECT = "hclc-online-report";
const PAGE_LIMIT = 100;
const MAX_PAGES = 40;
const DAY = 86400000;
const DIRECT_STATUSES = new Set(["completed", "new", "ready_to_ship", "shipped"]);
const REPORT_STATUSES = new Set([...DIRECT_STATUSES, "delivered", "pack"]);

function reportStatus(value) {
  const status = String(value || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  return ["pack", "packed", "to_pack", "to_be_packed"].includes(status) ? "pack" : status;
}

function validateSalesFilters(params) {
  const daily = params.get("daily") === "1";
  const grouped = daily && params.get("accounts") === "1";
  const requested = [...new Set(params.getAll("status"))];
  if (requested.some(status => !REPORT_STATUSES.has(status))) throw new RequestError(400, "Choose a supported order status.");
  const statuses = new Set(requested.length ? requested : ["completed"]);
  const first = statuses.values().next().value;
  return { daily, grouped, statuses, upstreamStatus: statuses.size === 1 && DIRECT_STATUSES.has(first) ? first : "" };
}

class RequestError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function json(body, status = 200) {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" }
  });
}

async function requestJson(url, options = {}) {
  const destination = new URL(url);
  const service = destination.hostname === "identitytoolkit.googleapis.com" ? "Firebase sign-in" :
    destination.pathname.endsWith("/get-paginated") ? "Zetpy orders" : "Zetpy authentication";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(url, { ...options, redirect: "manual", signal: controller.signal });
    if (response.status >= 300 && response.status < 400) {
      throw new RequestError(502, service + " returned an unexpected redirect. Ask the report owner to check the connection.");
    }
    let body;
    try { body = await response.json(); } catch (error) {
      if (controller.signal.aborted) throw error;
      body = null;
    }
    return { status: response.status, ok: response.ok, body };
  } catch (error) {
    if (error instanceof RequestError) throw error;
    const cause = controller.signal.aborted ? "timed out" : "could not be reached from Cloudflare";
    console.warn("Zetpy Sales upstream request failed", { service, cause, errorType: error?.name });
    throw new RequestError(502, service + " " + cause + ". Try again shortly.");
  } finally {
    clearTimeout(timer);
  }
}

function postJson(url, body) {
  return requestJson(url, {
    method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body)
  });
}

async function authorize(request, env) {
  const match = (request.headers.get("Authorization") || "").match(/^Bearer ([\w-]+\.[\w-]+\.[\w-]+)$/i);
  if (!match || match[1].length > 8192) throw new RequestError(401, "Sign in with Google again.");
  const approved = (env.ZETPY_APPROVED_EMAILS || "").split(/[\s,]+/).filter(Boolean).map(email => email.toLowerCase());
  if (!approved.length || !env.FIREBASE_WEB_API_KEY) {
    throw new RequestError(503, "Zetpy Sales access is awaiting Cloudflare setup.");
  }
  // Google validates the token. Read its claims only after a successful account lookup.
  const url = "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + encodeURIComponent(env.FIREBASE_WEB_API_KEY);
  const result = await postJson(url, { idToken: match[1] });
  if (!result.ok) {
    const code = result.body?.error?.message;
    if (["INVALID_ID_TOKEN", "TOKEN_EXPIRED", "USER_DISABLED", "USER_NOT_FOUND", "PROJECT_NUMBER_MISMATCH"].includes(code)) {
      throw new RequestError(401, "Your Google session is no longer valid. Sign in again.");
    }
    throw new RequestError(503, "Firebase could not verify the sign-in. Try again or contact the report owner.");
  }
  const user = result.body?.users?.[0];
  let claims;
  try {
    const segment = match[1].split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = segment.padEnd(Math.ceil(segment.length / 4) * 4, "=");
    claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(padded), char => char.charCodeAt(0))));
  } catch {
    throw new RequestError(401, "Your Google session could not be read. Sign in again.");
  }
  if (!user || claims.aud !== PROJECT || claims.iss !== "https://securetoken.google.com/" + PROJECT ||
      !user.localId || claims.sub !== user.localId || claims.firebase?.sign_in_provider !== "google.com" ||
      user.emailVerified !== true || !approved.includes(String(user.email || "").toLowerCase())) {
    throw new RequestError(403, "This Google account is not approved for Zetpy Sales.");
  }
}

function validateDates(params) {
  const from = params.get("from"), to = params.get("to");
  const valid = s => /^\d{4}-\d{2}-\d{2}$/.test(s || "") && Number.isFinite(Date.parse(s)) &&
    new Date(s).toISOString().slice(0, 10) === s;
  if (!valid(from) || !valid(to) || from > to || Date.parse(to) - Date.parse(from) >= 31 * DAY) {
    throw new RequestError(400, "Choose a valid date range of 1 to 31 days.");
  }
  return { from, to };
}

let tokenCache;
async function renew(env, current) {
  let result;
  if (current) result = await postJson(API + "account/refresh", { token: current });
  if (!result?.ok || result.body?.success !== true || !result.body?.token) {
    if (result?.status === 429) throw new RequestError(429, "Zetpy is limiting requests. Try again in a minute.");
    result = await postJson(API + "account/auth", { email: env.ZETPY_EMAIL, password: env.ZETPY_PASSWORD });
  }
  if (result.status === 429) throw new RequestError(429, "Zetpy is limiting requests. Try again in a minute.");
  if (!result.ok || result.body?.success !== true || typeof result.body.token !== "string" || !result.body.token) {
    throw new RequestError(502, "Zetpy could not authorize the connection. Ask the report owner to check its Cloudflare secrets.");
  }
  const seconds = Number(result.body.expires_in);
  const lifetime = Number.isFinite(seconds) && seconds > 0 ? seconds : 3600;
  tokenCache = { value: result.body.token, expires: Date.now() + Math.max(1, lifetime - 30) * 1000 };
  return tokenCache.value;
}

async function zetpyToken(env, rejected) {
  if (tokenCache?.value !== rejected && tokenCache?.expires > Date.now()) return tokenCache.value;
  // Keep upstream fetch promises inside their own Cloudflare request context.
  return renew(env, tokenCache?.value);
}

// Zetpy groups orders by marketplace, shop and order reference.
function collectOrders(value, orders, depth = 0) {
  if (!value || typeof value !== "object" || depth > 10) return;
  if (Array.isArray(value.items) || (value.items && typeof value.items === "object")) {
    orders.push(value);
    return;
  }
  for (const child of Object.values(value)) collectOrders(child, orders, depth + 1);
}

function collectSales(orders, seen, totals, groups, range, filters) {
  const { daily, grouped, statuses, upstreamStatus } = filters;
  let fresh = 0;
  for (const order of orders) {
    const platform = String(order.app_name || "").trim();
    const accountName = String(order.app_account_name || "").trim();
    const account = String(order.app_account_identifier || "").trim() || accountName;
    const reference = String(order.ref_no || order.app_internal_ref_id || order.id || "").trim();
    const status = reportStatus(order.status);
    if (!platform || !account || !reference || !status) {
      throw new RequestError(502, "Zetpy returned an order without its platform, shop, reference or status.");
    }
    if (upstreamStatus && status !== upstreamStatus) {
      throw new RequestError(502, "Zetpy returned an order outside the selected status. No totals were loaded.");
    }
    const key = JSON.stringify([platform, account, reference]);
    if (seen.has(key)) continue;
    seen.add(key);
    fresh++;
    if (!statuses.has(status)) continue;
    const day = daily ? String(order.created_date ?? "").slice(0, 10) : "";
    if (daily && (!/^\d{4}-\d{2}-\d{2}$/.test(day) || day < range.from || day > range.to ||
      !Number.isFinite(Date.parse(day)) || new Date(day).toISOString().slice(0, 10) !== day)) {
      throw new RequestError(502, "Zetpy returned a missing or out-of-range marketplace order date.");
    }
    const groupKey = JSON.stringify([platform, grouped ? account : "", grouped ? status : ""]);
    if (!groups.has(groupKey)) groups.set(groupKey, { platform, account, accountName: accountName || account, status, orders: 0 });
    groups.get(groupKey).orders++;
    const items = Object.values(order.items);
    if (!items.length) throw new RequestError(502, "A Zetpy order is missing its item details.");
    for (const item of items) {
      const sku = String(item?.sku ?? "").trim();
      const quantity = Number(item?.quantity_sold);
      if (!sku || item?.quantity_sold == null || item.quantity_sold === "" || !Number.isSafeInteger(quantity) || quantity < 0) {
        throw new RequestError(502, "A Zetpy order has a missing SKU or invalid quantity. No totals were loaded.");
      }
      const rowKey = JSON.stringify([day, groupKey, sku.toUpperCase()]);
      const row = totals.get(rowKey) || { ...(daily ? { day } : {}), ...(grouped ? { account, status } : {}), platform, sku, name: String(item.name || ""), units: 0 };
      row.units += quantity;
      totals.set(rowKey, row);
    }
  }
  return fresh;
}

async function loadSales(env, range, filters) {
  if (!env.ZETPY_EMAIL || !env.ZETPY_PASSWORD) throw new RequestError(503, "The report owner needs to add the Zetpy login secrets in Cloudflare.");
  const { daily, grouped, upstreamStatus } = filters;
  const seen = new Set(), totals = new Map(), groups = new Map();
  let token = await zetpyToken(env), reauthorized = false, finished = false;
  for (let page = 1; page <= MAX_PAGES; page++) {
    const query = new URLSearchParams({
      date_from: range.from, date_to: range.to, date_filter: "created_date",
      limit: String(PAGE_LIMIT), page: String(page), sort: "asc"
    });
    if (upstreamStatus) query.set("status", upstreamStatus);
    const requestPage = () => requestJson(API + "orders/get-paginated?" + query, {
      headers: { Authorization: "Bearer " + token, Accept: "application/json" }
    });
    let result = await requestPage();
    if (!reauthorized && (result.status === 401 || result.body?.error?.code === "token_error")) {
      reauthorized = true;
      token = await zetpyToken(env, token);
      result = await requestPage();
    }
    if (result.status === 429) throw new RequestError(429, "Zetpy is limiting requests. Try again in a minute or choose fewer days.");
    const { body } = result;
    const empty = result.ok && body?.success === false &&
      [body.error?.code, body.error?.error].includes("no_orders");
    if (empty) { finished = true; break; }
    if (!result.ok || body?.success !== true) throw new RequestError(502, "Zetpy could not return this sales period. Try again or choose fewer days.");
    const orders = [];
    collectOrders(body.data ?? body.orders ?? body, orders);
    const pagination = body.pagination ?? body.meta ?? body.data?.pagination ?? {};
    const last = Number(pagination.last_page ?? pagination.total_pages ?? body.last_page ?? body.total_pages);
    if (Number.isInteger(last) && last > MAX_PAGES) break;
    if (!orders.length) {
      const container = body.orders ?? body.data;
      if (container && typeof container === "object" && !Object.keys(container).length) {
        finished = true;
        break;
      }
      throw new RequestError(502, "Zetpy returned a response without readable order items.");
    }
    if (!collectSales(orders, seen, totals, groups, range, filters)) throw new RequestError(502, "Zetpy repeated an order page. Try a shorter date range.");
    if ((Number.isInteger(last) && last > 0 && page >= last) ||
        (Object.hasOwn(pagination, "next_page_url") && pagination.next_page_url === null)) {
      finished = true;
      break;
    }
  }
  if (!finished) throw new RequestError(422, "This period exceeds the order page limit. Choose fewer days.");
  const rows = [...totals.values()].sort((a, b) => b.units - a.units || a.platform.localeCompare(b.platform) || a.sku.localeCompare(b.sku));
  const orderGroups = [...groups.values()];
  const orders = orderGroups.reduce((total, group) => total + group.orders, 0);
  return { ...range, orders, ...(daily ? { dailyRows: rows } : { rows }), ...(grouped ? { orderGroups } : {}) };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/api/zetpy/sales") return env.ASSETS.fetch(request);
    if (request.method !== "GET") return json({ message: "Use GET to load sales." }, 405);
    try {
      const range = validateDates(url.searchParams);
      const filters = validateSalesFilters(url.searchParams);
      await authorize(request, env);
      return json(await loadSales(env, range, filters));
    } catch (error) {
      if (error instanceof RequestError) return json({ message: error.message }, error.status);
      console.error("Zetpy Sales processing failed", { errorType: error?.name });
      return json({ message: "Cloudflare could not process the sales response. Try again shortly." }, 502);
    }
  }
};
