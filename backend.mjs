const SESSION_LIFETIME = 30 * 24 * 60 * 60 * 1000;
const PASSWORD_ITERATIONS = 120000;
const encoder = new TextEncoder();
let adminReady = false;
let adminInitialization;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function reply(status, body, headers = {}) {
  return { status, body, headers, changed: false };
}

function jsonResponse(result) {
  const headers = new Headers(result.headers);
  headers.set('content-type', 'application/json; charset=utf-8');
  headers.set('cache-control', 'no-store');
  return new Response(JSON.stringify(result.body), { status: result.status, headers });
}

async function loadState(env) {
  return env.DB.load();
}

async function transact(env, operation) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const snapshot = await loadState(env);
    const result = operation(snapshot.state);
    if (!result.changed) return result;
    if (await env.DB.compareAndSwap(snapshot.version, snapshot.state)) return result;
  }
  throw new HttpError(503, '現在アクセスが集中しています。しばらくしてから再試行してください');
}

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function fromHex(value) {
  return Uint8Array.from(value.match(/.{2}/g) || [], (part) => Number.parseInt(part, 16));
}

async function digest(value) {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))));
}

async function hashPassword(password, salt, iterations = PASSWORD_ITERATIONS) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    hash: 'SHA-256',
    salt: fromHex(salt),
    iterations,
  }, key, 256);
  return hex(new Uint8Array(bits));
}

function secureEqual(left, right) {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return mismatch === 0;
}

function randomHex(length) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return hex(bytes);
}

function randomRaceId() {
  const bytes = crypto.getRandomValues(new Uint8Array(9));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function cookieMap(request) {
  const cookies = Object.fromEntries((request.headers.get('cookie') || '').split(';').map((part) => {
    const separator = part.indexOf('=');
    return separator < 0 ? ['', ''] : [part.slice(0, separator).trim(), part.slice(separator + 1).trim()];
  }).filter(([name]) => name));
  const sessionHeader = request.headers.get('x-sokuho-session');
  if (sessionHeader) cookies.sokuho_session = sessionHeader;
  return cookies;
}

function sessionCookie(request, token, maxAge = SESSION_LIFETIME / 1000) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `sokuho_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

function currentUser(state, tokenHash) {
  if (!tokenHash) return null;
  const session = state.accounts.sessions[tokenHash];
  if (!session || session.expiresAt <= Date.now()) return null;
  const user = state.accounts.users.find((item) => item.id === session.userId);
  return user ? { id: user.id, name: user.name, email: user.email, role: user.role } : null;
}

function ownsRace(user, race) {
  return user?.role === 'organizer' && race.ownerId === user.id;
}

function collaboratesOnRace(user, race) {
  return user?.role === 'organizer' && (race.collaborationGroup?.memberIds || []).includes(user.id);
}

function canManageRace(user, race) {
  return ownsRace(user, race) || collaboratesOnRace(user, race);
}

function accountLabel(accounts, userId) {
  const user = accounts.users.find((item) => item.id === userId);
  return user ? { id: user.id, name: user.name, email: user.email } : null;
}

function groupDetails(race, accounts) {
  if (!race.collaborationGroup) return null;
  return {
    createdAt: race.collaborationGroup.createdAt,
    owner: accountLabel(accounts, race.ownerId),
    members: race.collaborationGroup.memberIds.map((id) => accountLabel(accounts, id)).filter(Boolean),
  };
}

function publicRace(race) {
  const { ownerId, collaborationGroup, ...publicData } = race;
  return publicData;
}

function organizerRaceDetails(race, user, accounts) {
  return {
    ...publicRace(race),
    owner: accountLabel(accounts, race.ownerId),
    relation: ownsRace(user, race) ? 'owner' : 'collaborator',
    groupMemberCount: race.collaborationGroup?.memberIds.length || 0,
  };
}

async function ensureAdmin(env) {
  const email = String(env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = env.ADMIN_PASSWORD || '';
  if (!email || !password) return;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12) {
    throw new Error('ADMIN_EMAILと12文字以上のADMIN_PASSWORDを設定してください');
  }
  if (adminReady) return;
  if (!adminInitialization) {
    adminInitialization = initializeAdmin(env, email, password)
      .then(() => { adminReady = true; })
      .catch((error) => {
        adminInitialization = null;
        throw error;
      });
  }
  await adminInitialization;
}

async function initializeAdmin(env, email, password) {
  const { state } = await loadState(env);
  if (state.accounts.users.some((user) => user.email === email && user.role === 'admin')) return;
  const salt = randomHex(16);
  const passwordHash = await hashPassword(password, salt);
  const result = await transact(env, (latest) => {
    const existingUser = latest.accounts.users.find((user) => user.email === email);
    if (existingUser?.role === 'admin') return reply(200, {});
    if (existingUser) throw new Error('ADMIN_EMAIL is already registered as an organizer; use a separate email');
    latest.accounts.users.push({
      id: crypto.randomUUID(),
      name: '管理者',
      email,
      role: 'admin',
      salt,
      passwordHash,
      hashIterations: PASSWORD_ITERATIONS,
      createdAt: Date.now(),
    });
    const created = reply(201, {});
    created.changed = true;
    return created;
  });
  if (result.status === 201) console.log('Administrator account initialized');
}

async function requestBody(request) {
  const text = await request.text();
  if (text.length > 1_000_000) throw new HttpError(413, 'リクエストが大きすぎます');
  try {
    return JSON.parse(text || '{}');
  } catch {
    throw new HttpError(400, 'JSONの形式が正しくありません');
  }
}

function statusForUser(user) {
  return user ? 403 : 401;
}

async function routeApi(request, env, url, user, tokenHash) {
  const { pathname } = url;

  if (pathname === '/api/auth/me' && request.method === 'GET') return reply(200, { user });

  if (pathname === '/api/auth/register' && request.method === 'POST') {
    const body = await requestBody(request);
    const name = String(body.name || '').trim().slice(0, 60);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12) {
      return reply(400, { error: '名前、正しいメールアドレス、12文字以上のパスワードを入力してください' });
    }
    const salt = randomHex(16);
    const passwordHash = await hashPassword(password, salt);
    const token = randomHex(32);
    const sessionId = await digest(token);
    const result = await transact(env, (state) => {
      if (state.accounts.users.some((item) => item.email === email)) {
        return reply(409, { error: 'このメールアドレスは登録済みです' });
      }
      const newUser = {
        id: crypto.randomUUID(),
        name,
        email,
        role: 'organizer',
        salt,
        passwordHash,
        hashIterations: PASSWORD_ITERATIONS,
        createdAt: Date.now(),
      };
      state.accounts.users.push(newUser);
      state.accounts.sessions[sessionId] = { userId: newUser.id, expiresAt: Date.now() + SESSION_LIFETIME };
      const created = reply(201, { user: { id: newUser.id, name, email, role: newUser.role } }, {
        'set-cookie': sessionCookie(request, token),
        'x-sokuho-session': token,
      });
      created.changed = true;
      return created;
    });
    return result;
  }

  if (pathname === '/api/auth/login' && request.method === 'POST') {
    const body = await requestBody(request);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const { state } = await loadState(env);
    const foundUser = state.accounts.users.find((item) => item.email === email);
    const salt = foundUser?.salt || '00000000000000000000000000000000';
    const iterations = foundUser?.hashIterations || PASSWORD_ITERATIONS;
    const actualHash = await hashPassword(password, salt, iterations);
    if (!foundUser || !secureEqual(actualHash, foundUser.passwordHash)) {
      return reply(401, { error: 'メールアドレスまたはパスワードが違います' });
    }
    const token = randomHex(32);
    const sessionId = await digest(token);
    const result = await transact(env, (latest) => {
      const latestUser = latest.accounts.users.find((item) => item.id === foundUser.id);
      if (!latestUser) return reply(401, { error: 'メールアドレスまたはパスワードが違います' });
      latest.accounts.sessions[sessionId] = { userId: latestUser.id, expiresAt: Date.now() + SESSION_LIFETIME };
      const loggedIn = reply(200, {
        user: { id: latestUser.id, name: latestUser.name, email, role: latestUser.role },
      }, { 'set-cookie': sessionCookie(request, token), 'x-sokuho-session': token });
      loggedIn.changed = true;
      return loggedIn;
    });
    return result;
  }

  if (pathname === '/api/auth/logout' && request.method === 'POST') {
    const result = await transact(env, (state) => {
      if (tokenHash) delete state.accounts.sessions[tokenHash];
      const loggedOut = reply(200, { ok: true }, {
        'set-cookie': sessionCookie(request, '', 0),
        'x-sokuho-session': '',
      });
      loggedOut.changed = Boolean(tokenHash);
      return loggedOut;
    });
    return result;
  }

  if (pathname === '/api/time' && request.method === 'GET') return reply(200, { serverTime: Date.now() });

  if (pathname === '/api/admin/summary' && request.method === 'GET') {
    if (user?.role !== 'admin') return reply(statusForUser(user), { error: '管理者専用です' });
    const { state } = await loadState(env);
    const organizers = state.accounts.users.filter((item) => item.role === 'organizer');
    const races = Object.values(state.races);
    return reply(200, {
      organizerCount: organizers.length,
      raceCount: races.length,
      organizers: organizers.map(({ id, name, email, createdAt }) => ({
        id,
        name,
        email,
        createdAt,
        ownedRaceCount: races.filter((race) => race.ownerId === id).length,
        collaborationCount: races.filter((race) => (race.collaborationGroup?.memberIds || []).includes(id)).length,
      })),
      races: races.map((race) => ({
        id: race.id,
        title: race.title,
        owner: accountLabel(state.accounts, race.ownerId),
        collaborators: groupDetails(race, state.accounts)?.members || [],
        createdAt: race.createdAt,
      })),
    });
  }

  if (pathname.startsWith('/api/admin/') && request.method === 'DELETE') {
    if (user?.role !== 'admin') return reply(statusForUser(user), { error: '管理者専用です' });
    const raceMatch = pathname.match(/^\/api\/admin\/races\/([A-Za-z0-9_-]{12})$/);
    if (raceMatch) {
      return transact(env, (state) => {
        if (!state.races[raceMatch[1]]) return reply(404, { error: '大会が見つかりません' });
        delete state.races[raceMatch[1]];
        const deleted = reply(200, { ok: true });
        deleted.changed = true;
        return deleted;
      });
    }
    const organizerMatch = pathname.match(/^\/api\/admin\/organizers\/([0-9a-f-]{36})$/i);
    if (organizerMatch) {
      return transact(env, (state) => {
        const organizerId = organizerMatch[1];
        const organizer = state.accounts.users.find((item) => item.id === organizerId && item.role === 'organizer');
        if (!organizer) return reply(404, { error: '運営者アカウントが見つかりません' });
        let deletedRaces = 0;
        for (const [raceId, race] of Object.entries(state.races)) {
          if (race.ownerId === organizerId) {
            delete state.races[raceId];
            deletedRaces += 1;
          } else if (race.collaborationGroup?.memberIds.includes(organizerId)) {
            race.collaborationGroup.memberIds = race.collaborationGroup.memberIds.filter((id) => id !== organizerId);
          }
        }
        state.accounts.users = state.accounts.users.filter((item) => item.id !== organizerId);
        for (const [id, session] of Object.entries(state.accounts.sessions)) {
          if (session.userId === organizerId) delete state.accounts.sessions[id];
        }
        const deleted = reply(200, { ok: true, deletedRaces });
        deleted.changed = true;
        return deleted;
      });
    }
    return reply(404, { error: '削除対象が見つかりません' });
  }

  if (pathname === '/api/races' && request.method === 'GET') {
    if (user?.role !== 'organizer') return reply(statusForUser(user), { error: '運営者としてログインしてください' });
    const { state } = await loadState(env);
    const races = Object.values(state.races).filter((race) => canManageRace(user, race));
    return reply(200, races.map((race) => organizerRaceDetails(race, user, state.accounts)));
  }

  if (pathname === '/api/races' && request.method === 'POST') {
    const body = await requestBody(request);
    if (user?.role !== 'organizer') return reply(statusForUser(user), { error: '大会作成には運営者ログインが必要です' });
    const title = String(body.title || '').trim().slice(0, 80);
    if (!title) return reply(400, { error: '大会名を入力してください' });
    return transact(env, (state) => {
      const race = {
        id: randomRaceId(),
        ownerId: user.id,
        collaborationGroup: null,
        title,
        date: String(body.date || '').slice(0, 10),
        venue: String(body.venue || '').trim().slice(0, 80),
        createdAt: Date.now(),
        events: [],
      };
      state.races[race.id] = race;
      const created = reply(201, race);
      created.changed = true;
      return created;
    });
  }

  const racePath = pathname.match(/^\/api\/races\/([A-Za-z0-9_-]{12})(?:\/(.*))?$/);
  if (!racePath) return reply(404, { error: 'ページが見つかりません' });
  const raceId = racePath[1];
  const actionParts = (racePath[2] || '').split('/');
  const action = actionParts[0] || '';
  const subaction = actionParts[1] || '';
  const memberId = actionParts[2] || '';
  const { state } = await loadState(env);
  const race = state.races[raceId];
  if (!race) return reply(404, { error: '大会が見つかりません' });

  if (action === 'snapshot' && request.method === 'GET') {
    const canManage = canManageRace(user, race);
    return reply(200, {
      race: publicRace(race),
      access: {
        canManage,
        isOwner: ownsRace(user, race),
        isCollaborator: collaboratesOnRace(user, race),
      },
      group: canManage ? groupDetails(race, state.accounts) : null,
    });
  }

  if (action === 'access' && request.method === 'GET') {
    if (user?.role !== 'organizer') return reply(statusForUser(user), { error: '運営者としてログインしてください' });
    return reply(200, {
      canManage: canManageRace(user, race),
      isOwner: ownsRace(user, race),
      isCollaborator: collaboratesOnRace(user, race),
    });
  }

  if (action === 'group') {
    if (request.method === 'GET') {
      if (!canManageRace(user, race)) return reply(statusForUser(user), { error: 'この大会グループを表示する権限がありません' });
      return reply(200, { group: groupDetails(race, state.accounts) });
    }
    if (!ownsRace(user, race)) return reply(statusForUser(user), { error: '共同運営グループを管理できるのは大会主催者だけです' });
    if (request.method === 'POST' && !subaction) {
      return transact(env, (latest) => {
        const latestRace = latest.races[raceId];
        if (!latestRace || !ownsRace(user, latestRace)) return reply(403, { error: 'この大会グループを変更する権限がありません' });
        if (latestRace.collaborationGroup) return reply(409, { error: '共同運営グループは作成済みです' });
        latestRace.collaborationGroup = { createdAt: Date.now(), memberIds: [] };
        const created = reply(201, { group: groupDetails(latestRace, latest.accounts) });
        created.changed = true;
        return created;
      });
    }
    if (subaction === 'members' && request.method === 'POST') {
      const body = await requestBody(request);
      const email = String(body.email || '').trim().toLowerCase();
      return transact(env, (latest) => {
        const latestRace = latest.races[raceId];
        if (!latestRace || !ownsRace(user, latestRace)) return reply(403, { error: 'この大会グループを変更する権限がありません' });
        if (!latestRace.collaborationGroup) return reply(409, { error: '先に共同運営グループを作成してください' });
        const invited = latest.accounts.users.find((item) => item.email === email && item.role === 'organizer');
        if (!invited) return reply(404, { error: 'このメールアドレスの運営者アカウントが見つかりません' });
        if (invited.id === latestRace.ownerId || latestRace.collaborationGroup.memberIds.includes(invited.id)) {
          return reply(409, { error: 'この運営者はすでにグループに参加しています' });
        }
        latestRace.collaborationGroup.memberIds.push(invited.id);
        const updated = reply(201, { group: groupDetails(latestRace, latest.accounts) });
        updated.changed = true;
        return updated;
      });
    }
    if (subaction === 'members' && memberId && request.method === 'DELETE') {
      return transact(env, (latest) => {
        const latestRace = latest.races[raceId];
        if (!latestRace || !ownsRace(user, latestRace)) return reply(403, { error: 'この大会グループを変更する権限がありません' });
        if (!latestRace.collaborationGroup?.memberIds.includes(memberId)) {
          return reply(404, { error: '共同運営者が見つかりません' });
        }
        latestRace.collaborationGroup.memberIds = latestRace.collaborationGroup.memberIds.filter((id) => id !== memberId);
        const updated = reply(200, { group: groupDetails(latestRace, latest.accounts) });
        updated.changed = true;
        return updated;
      });
    }
    return reply(405, { error: 'このグループ操作には対応していません' });
  }

  if (['events', 'start', 'finish'].includes(action) && !canManageRace(user, race)) {
    return reply(statusForUser(user), { error: 'この大会を操作する権限がありません' });
  }
  if (request.method === 'GET' && !action) return reply(200, publicRace(race));

  if (request.method === 'POST' && action === 'events') {
    const body = await requestBody(request);
    const name = String(body.name || '').trim().slice(0, 60);
    const round = String(body.round || '').trim().slice(0, 30);
    const athletes = Array.isArray(body.athletes) ? body.athletes.slice(0, 12) : [];
    if (!name || athletes.length === 0) return reply(400, { error: '競技名と選手を入力してください' });
    const event = {
      id: crypto.randomUUID(),
      name,
      round,
      status: 'ready',
      startedAt: null,
      athletes: athletes.map((athlete, index) => ({
        id: crypto.randomUUID(),
        lane: index + 1,
        name: String(athlete.name || '').trim().slice(0, 50),
        team: String(athlete.team || '').trim().slice(0, 50),
        finishedAt: null,
      })).filter((athlete) => athlete.name),
    };
    if (event.athletes.length === 0) return reply(400, { error: '選手名を入力してください' });
    return transact(env, (latest) => {
      const latestRace = latest.races[raceId];
      if (!latestRace) return reply(404, { error: '大会が見つかりません' });
      if (!canManageRace(user, latestRace)) return reply(403, { error: 'この大会を操作する権限がありません' });
      latestRace.events.push(event);
      const created = reply(201, { race: latestRace, event });
      created.changed = true;
      return created;
    });
  }

  if (request.method === 'POST' && (action === 'start' || action === 'finish')) {
    const body = await requestBody(request);
    const clientTime = Number(body.clientTime);
    if (!Number.isFinite(clientTime) || clientTime < 0) return reply(400, { error: '時刻を取得できませんでした' });
    return transact(env, (latest) => {
      const latestRace = latest.races[raceId];
      if (!latestRace) return reply(404, { error: '大会が見つかりません' });
      if (!canManageRace(user, latestRace)) return reply(403, { error: 'この大会を操作する権限がありません' });
      const event = latestRace.events.find((item) => item.id === body.eventId);
      if (!event) return reply(404, { error: '競技が見つかりません' });
      if (action === 'start') {
        if (event.startedAt) return reply(409, { error: 'この組はすでにスタートしています' });
        event.startedAt = clientTime;
        event.status = 'running';
      } else {
        const athlete = event.athletes.find((item) => item.id === body.athleteId);
        if (!athlete) return reply(404, { error: '選手が見つかりません' });
        if (!event.startedAt) return reply(409, { error: '先にスタートを記録してください' });
        if (athlete.finishedAt) return reply(409, { error: 'この選手の記録は登録済みです' });
        if (clientTime <= event.startedAt) return reply(400, { error: 'フィニッシュ時刻がスタート時刻より前です' });
        athlete.finishedAt = clientTime;
        if (event.athletes.every((item) => item.finishedAt)) event.status = 'complete';
      }
      const updated = reply(200, { race: latestRace });
      updated.changed = true;
      return updated;
    });
  }

  return reply(405, { error: 'この操作には対応していません' });
}

async function serveAsset(request, env, pathname) {
  if (pathname === '/' || pathname === '/admin' || pathname === '/login' || /^\/r\/[A-Za-z0-9_-]{12}$/.test(pathname)) {
    const indexUrl = new URL(request.url);
    indexUrl.pathname = '/';
    return env.ASSETS.fetch(new Request(indexUrl, request));
  }
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const functionPrefix = '/functions/v1/api';
      if (url.pathname.startsWith(functionPrefix)) {
        url.pathname = url.pathname.slice(functionPrefix.length) || '/';
      }
      if (url.pathname === '/healthz' && request.method === 'GET') {
        await loadState(env);
        return new Response('ok', { headers: { 'cache-control': 'no-store' } });
      }
      if (url.pathname.startsWith('/api/')) {
        await ensureAdmin(env);
        const token = cookieMap(request).sokuho_session;
        const tokenHash = token ? await digest(token) : null;
        const { state } = await loadState(env);
        const user = currentUser(state, tokenHash);
        return jsonResponse(await routeApi(request, env, url, user, tokenHash));
      }
      return serveAsset(request, env, url.pathname);
    } catch (error) {
      console.error(error);
      const status = error instanceof HttpError ? error.status : 500;
      const message = error instanceof HttpError ? error.message : 'サーバーエラーが発生しました';
      return jsonResponse(reply(status, { error: message }));
    }
  },
};
