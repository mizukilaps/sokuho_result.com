const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const port = Number(process.env.PORT || 4173);
const publicDir = path.join(__dirname, 'public');
const dataDir = path.join(__dirname, 'data');
const dataFile = path.join(dataDir, 'races.json');
const accountsFile = path.join(dataDir, 'accounts.json');
const clients = new Map();
const UN_MEMBER_COUNTRY_CODES = require('./un-member-country-codes.json');
const sessionLifetime = 30 * 24 * 60 * 60 * 1000;
const defaultMaintenanceMessage = 'メンテナンス中です。復旧までしばらくお待ちください。';
const countryDisplayNames = new Intl.DisplayNames(['ja'], { type: 'region' });

fs.mkdirSync(dataDir, { recursive: true });

function readRaces() {
  try {
    return JSON.parse(fs.readFileSync(dataFile, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw error;
  }
}

function saveRaces(races) {
  const temporaryFile = `${dataFile}.tmp`;
  fs.writeFileSync(temporaryFile, JSON.stringify(races, null, 2));
  fs.renameSync(temporaryFile, dataFile);
}

function readAccounts() {
  try {
    const accounts = JSON.parse(fs.readFileSync(accountsFile, 'utf8'));
    accounts.supportTickets ||= [];
    accounts.announcements ||= [];
    accounts.auditLog ||= [];
    accounts.venues ||= [];
    accounts.venueRequests ||= [];
    accounts.maintenance ||= { enabled: false, message: defaultMaintenanceMessage };
    return accounts;
  } catch (error) {
    if (error.code === 'ENOENT') return {
      users: [],
      sessions: {},
      supportTickets: [],
      announcements: [],
      auditLog: [],
      venues: [],
      venueRequests: [],
      maintenance: { enabled: false, message: defaultMaintenanceMessage },
    };
    throw error;
  }
}

function venueCountryCode(venue) {
  if (UN_MEMBER_COUNTRY_CODES.includes(venue.countryCode)) return venue.countryCode;
  return venue.type === 'domestic' ? 'JP' : '';
}

function venueCodeFor(venue) {
  const id = String(venue.id || '').replaceAll('-', '');
  if (!/^[0-9a-f]{32}$/i.test(id)) throw new Error('Invalid venue ID');
  return BigInt(`0x${id}`).toString(10);
}

function venueDetails(venue) {
  const countryCode = venueCountryCode(venue);
  return {
    ...venue,
    countryCode,
    country: countryCode ? countryDisplayNames.of(countryCode) : '',
    sokuhoCode: venueCodeFor(venue),
  };
}

function normalizeVenuePart(value) {
  return String(value || '').trim().normalize('NFKC').toLocaleLowerCase();
}

function matchesVenue(left, right) {
  return venueCountryCode(left) === right.countryCode
    && normalizeVenuePart(left.name) === normalizeVenuePart(right.name)
    && normalizeVenuePart(left.location) === normalizeVenuePart(right.location);
}

function maintenanceSettings(accounts) {
  const settings = accounts.maintenance || {};
  return {
    enabled: settings.enabled === true,
    message: typeof settings.message === 'string' && settings.message.trim()
      ? settings.message.trim()
      : defaultMaintenanceMessage,
  };
}

function saveAccounts(accounts) {
  const temporaryFile = `${accountsFile}.tmp`;
  fs.writeFileSync(temporaryFile, JSON.stringify(accounts, null, 2), { mode: 0o600 });
  fs.renameSync(temporaryFile, accountsFile);
  fs.chmodSync(accountsFile, 0o600);
}

function passwordHash(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey.toString('hex'));
    });
  });
}

function cookieMap(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').map((part) => {
    const separator = part.indexOf('=');
    return separator < 0 ? ['', ''] : [part.slice(0, separator).trim(), part.slice(separator + 1).trim()];
  }).filter(([name]) => name));
}

function sessionCookie(request, token, maxAge = sessionLifetime / 1000) {
  const secure = request.socket.encrypted || request.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `sokuho_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

function currentUser(request) {
  const token = cookieMap(request).sokuho_session;
  if (!token) return null;
  const accounts = readAccounts();
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const session = accounts.sessions[tokenHash];
  if (!session || session.expiresAt <= Date.now()) return null;
  const user = accounts.users.find((item) => item.id === session.userId);
  return user ? {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    mustChangePassword: Boolean(user.mustChangePassword),
  } : null;
}

function createSession(request, response, user, accounts) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  accounts.sessions[tokenHash] = { userId: user.id, expiresAt: Date.now() + sessionLifetime };
  saveAccounts(accounts);
  response.setHeader('set-cookie', sessionCookie(request, token));
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

function addAuditEntry(accounts, user, race, action, before, after) {
  accounts.auditLog ||= [];
  accounts.auditLog.push({
    id: crypto.randomUUID(),
    actorId: user.id,
    actorRole: user.role,
    raceId: race.id,
    raceTitle: race.title,
    action,
    before: structuredClone(before),
    after: structuredClone(after),
    createdAt: Date.now(),
  });
}

function groupDetails(race, accounts) {
  if (!race.collaborationGroup) return null;
  return {
    createdAt: race.collaborationGroup.createdAt,
    owner: accountLabel(accounts, race.ownerId),
    members: race.collaborationGroup.memberIds.map((id) => accountLabel(accounts, id)).filter(Boolean),
  };
}

function organizerRaceDetails(race, user, accounts) {
  return {
    ...publicRace(race),
    owner: accountLabel(accounts, race.ownerId),
    relation: ownsRace(user, race) ? 'owner' : 'collaborator',
    groupMemberCount: race.collaborationGroup?.memberIds.length || 0,
  };
}

async function initializeAdmin() {
  const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!email || !password) return;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12) {
    throw new Error('ADMIN_EMAILと12文字以上のADMIN_PASSWORDを設定してください');
  }
  const accounts = readAccounts();
  const existingUser = accounts.users.find((user) => user.email === email);
  if (existingUser?.role === 'admin') return;
  if (existingUser) throw new Error('ADMIN_EMAIL is already registered as an organizer; use a separate email');
  const salt = crypto.randomBytes(16).toString('hex');
  accounts.users.push({
    id: crypto.randomUUID(),
    name: '管理者',
    email,
    role: 'admin',
    salt,
    passwordHash: await passwordHash(password, salt),
    createdAt: Date.now(),
  });
  saveAccounts(accounts);
  console.log(`Administrator account initialized for ${email}`);
}

function sendJson(response, status, value) {
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  response.end(JSON.stringify(value));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error('リクエストが大きすぎます'));
        request.destroy();
      }
    });
    request.on('end', () => {
      try {
        resolve(JSON.parse(body || '{}'));
      } catch {
        reject(new Error('JSONの形式が正しくありません'));
      }
    });
    request.on('error', reject);
  });
}

function publicRace(race) {
  const { ownerId, collaborationGroup, ...publicData } = race;
  return publicData;
}

function broadcast(race) {
  const raceClients = clients.get(race.id);
  if (!raceClients) return;
  const message = `event: race\ndata: ${JSON.stringify(publicRace(race))}\n\n`;
  for (const response of raceClients) response.write(message);
}

function closeDeletedRace(raceId) {
  const raceClients = clients.get(raceId);
  if (!raceClients) return;
  for (const response of raceClients) {
    response.write('event: deleted\ndata: {}\n\n');
    response.end();
  }
  clients.delete(raceId);
}

function routeRace(request, response, url, user, maintenanceEnabled) {
  const [, , , raceId, action, subaction, memberId] = url.pathname.split('/');
  const races = readRaces();
  const race = races[raceId];
  if (!race) {
    sendJson(response, 404, { error: '大会が見つかりません' });
    return;
  }

  if (action === 'snapshot' && request.method === 'GET') {
    const canManage = !maintenanceEnabled && canManageRace(user, race);
    sendJson(response, 200, {
      race: publicRace(race),
      access: {
        canManage,
        isOwner: ownsRace(user, race),
        isCollaborator: collaboratesOnRace(user, race),
      },
      group: canManage ? groupDetails(race, readAccounts()) : null,
    });
    return;
  }

  if (action === 'access' && request.method === 'GET') {
    if (user?.role !== 'organizer') {
      sendJson(response, user ? 403 : 401, { error: '運営者としてログインしてください' });
      return;
    }
    sendJson(response, 200, {
      canManage: canManageRace(user, race),
      isOwner: ownsRace(user, race),
      isCollaborator: collaboratesOnRace(user, race),
    });
    return;
  }

  if (action === 'group') {
    const accounts = readAccounts();
    if (request.method === 'GET') {
      if (!canManageRace(user, race)) {
        sendJson(response, user ? 403 : 401, { error: 'この大会グループを表示する権限がありません' });
        return;
      }
      sendJson(response, 200, { group: groupDetails(race, accounts) });
      return;
    }

    if (!ownsRace(user, race)) {
      sendJson(response, user ? 403 : 401, { error: '共同運営グループを管理できるのは大会主催者だけです' });
      return;
    }

    if (request.method === 'POST' && !subaction) {
      if (race.collaborationGroup) {
        sendJson(response, 409, { error: '共同運営グループは作成済みです' });
        return;
      }
      race.collaborationGroup = { createdAt: Date.now(), memberIds: [] };
      saveRaces(races);
      broadcast(race);
      sendJson(response, 201, { group: groupDetails(race, accounts) });
      return;
    }

    if (subaction === 'members' && request.method === 'POST') {
      readBody(request).then((body) => {
        const latestRaces = readRaces();
        const latestRace = latestRaces[raceId];
        if (!latestRace || !ownsRace(user, latestRace)) {
          sendJson(response, 403, { error: 'この大会グループを変更する権限がありません' });
          return;
        }
        if (!latestRace.collaborationGroup) {
          sendJson(response, 409, { error: '先に共同運営グループを作成してください' });
          return;
        }
        const email = String(body.email || '').trim().toLowerCase();
        const latestAccounts = readAccounts();
        const invited = latestAccounts.users.find((item) => item.email === email && item.role === 'organizer');
        if (!invited) {
          sendJson(response, 404, { error: 'このメールアドレスの運営者アカウントが見つかりません' });
          return;
        }
        if (invited.id === latestRace.ownerId || latestRace.collaborationGroup.memberIds.includes(invited.id)) {
          sendJson(response, 409, { error: 'この運営者はすでにグループに参加しています' });
          return;
        }
        latestRace.collaborationGroup.memberIds.push(invited.id);
        saveRaces(latestRaces);
        broadcast(latestRace);
        sendJson(response, 201, { group: groupDetails(latestRace, latestAccounts) });
      }).catch((error) => sendJson(response, 400, { error: error.message }));
      return;
    }

    if (subaction === 'members' && memberId && request.method === 'DELETE') {
      if (!race.collaborationGroup?.memberIds.includes(memberId)) {
        sendJson(response, 404, { error: '共同運営者が見つかりません' });
        return;
      }
      race.collaborationGroup.memberIds = race.collaborationGroup.memberIds.filter((id) => id !== memberId);
      saveRaces(races);
      broadcast(race);
      sendJson(response, 200, { group: groupDetails(race, accounts) });
      return;
    }

    sendJson(response, 405, { error: 'このグループ操作には対応していません' });
    return;
  }

  if (['events', 'start', 'finish'].includes(action) && !canManageRace(user, race)) {
    sendJson(response, user ? 403 : 401, { error: 'この大会を操作する権限がありません' });
    return;
  }

  if (action === 'events' && request.method === 'PATCH') {
    readBody(request).then((body) => {
      const latestRaces = readRaces();
      const latestRace = latestRaces[raceId];
      if (!latestRace || !canManageRace(user, latestRace)) {
        sendJson(response, 403, { error: 'この大会を操作する権限がありません' });
        return;
      }
      const accounts = readAccounts();
      if (subaction === 'order') {
        const eventIds = Array.isArray(body.eventIds) ? body.eventIds : [];
        const currentIds = latestRace.events.map((item) => item.id);
        if (eventIds.length !== currentIds.length
          || new Set(eventIds).size !== currentIds.length
          || eventIds.some((id) => !currentIds.includes(id))) {
          sendJson(response, 400, { error: '競技順のデータが正しくありません' });
          return;
        }
        const before = latestRace.events.map(({ id, name, round }) => ({ id, name, round }));
        const byId = new Map(latestRace.events.map((item) => [item.id, item]));
        latestRace.events = eventIds.map((id) => byId.get(id));
        const after = latestRace.events.map(({ id, name, round }) => ({ id, name, round }));
        addAuditEntry(accounts, user, latestRace, 'event_order_changed', before, after);
        saveRaces(latestRaces);
        saveAccounts(accounts);
        broadcast(latestRace);
        sendJson(response, 200, { race: latestRace });
        return;
      }

      const event = latestRace.events.find((item) => item.id === subaction);
      if (!event) {
        sendJson(response, 404, { error: '競技が見つかりません' });
        return;
      }
      const name = String(body.name || '').trim().slice(0, 60);
      const round = String(body.round || '').trim().slice(0, 30);
      const athletes = Array.isArray(body.athletes) ? body.athletes : [];
      const startedAt = body.startedAt === null || body.startedAt === '' ? null : Number(body.startedAt);
      const scheduledAt = body.scheduledAt === null || body.scheduledAt === '' ? null : Number(body.scheduledAt);
      if (!name || !athletes.length || athletes.length > 12
        || (startedAt !== null && (!Number.isFinite(startedAt) || startedAt < 0))
        || (scheduledAt !== null && (!Number.isFinite(scheduledAt) || scheduledAt < 0))) {
        sendJson(response, 400, { error: '競技名、選手、開始予定・記録時刻を確認してください' });
        return;
      }
      const knownIds = new Set(event.athletes.map((item) => item.id));
      const ids = athletes.map((item) => String(item.id || '')).filter(Boolean);
      if (new Set(ids).size !== ids.length || ids.some((id) => !knownIds.has(id))) {
        sendJson(response, 400, { error: '選手データが正しくありません。画面を再読み込みしてください' });
        return;
      }
      const updatedAthletes = athletes.map((athlete, index) => {
        const current = athlete.id ? event.athletes.find((item) => item.id === athlete.id) : null;
        const finishedAt = athlete.finishedAt === null || athlete.finishedAt === '' ? null : Number(athlete.finishedAt);
        return {
          id: current?.id || crypto.randomUUID(),
          lane: index + 1,
          name: String(athlete.name || '').trim().slice(0, 50),
          team: String(athlete.team || '').trim().slice(0, 50),
          grade: String(athlete.grade || '').trim().slice(0, 30),
          finishedAt,
        };
      });
      if (updatedAthletes.some((item) => !item.name
        || (item.finishedAt !== null && (!Number.isFinite(item.finishedAt) || item.finishedAt < 0
          || startedAt === null || item.finishedAt <= startedAt)))) {
        sendJson(response, 400, { error: '選手名と、スタート後の正しいフィニッシュ時刻を入力してください' });
        return;
      }
      const before = structuredClone(event);
      event.name = name;
      event.round = round;
      event.startedAt = startedAt;
      event.scheduledAt = scheduledAt;
      event.athletes = updatedAthletes;
      event.status = startedAt === null ? 'ready'
        : updatedAthletes.every((item) => item.finishedAt !== null) ? 'complete'
          : 'running';
      addAuditEntry(accounts, user, latestRace, 'event_updated', before, event);
      saveRaces(latestRaces);
      saveAccounts(accounts);
      broadcast(latestRace);
      sendJson(response, 200, { race: latestRace, event });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (request.method === 'GET' && action === 'stream') {
    response.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
    });
    response.write(`event: race\ndata: ${JSON.stringify(publicRace(race))}\n\n`);
    const raceClients = clients.get(raceId) || new Set();
    raceClients.add(response);
    clients.set(raceId, raceClients);
    request.on('close', () => {
      raceClients.delete(response);
      if (raceClients.size === 0) clients.delete(raceId);
    });
    return;
  }

  if (request.method === 'POST' && action === 'events') {
    readBody(request).then((body) => {
      const latestRaces = readRaces();
      const latestRace = latestRaces[raceId];
      if (!latestRace) {
        sendJson(response, 404, { error: '大会が見つかりません' });
        return;
      }
      const name = String(body.name || '').trim().slice(0, 60);
      const round = String(body.round || '').trim().slice(0, 30);
      const athletes = Array.isArray(body.athletes) ? body.athletes.slice(0, 12) : [];
      const scheduledAt = body.scheduledAt === null || body.scheduledAt === '' || body.scheduledAt === undefined
        ? null
        : Number(body.scheduledAt);
      if (!name || athletes.length === 0
        || (scheduledAt !== null && (!Number.isFinite(scheduledAt) || scheduledAt < 0))) {
        sendJson(response, 400, { error: '競技名と選手を入力してください' });
        return;
      }
      const event = {
        id: crypto.randomUUID(),
        name,
        round,
        scheduledAt,
        status: 'ready',
        startedAt: null,
        athletes: athletes.map((athlete, index) => ({
          id: crypto.randomUUID(),
          lane: index + 1,
          name: String(athlete.name || '').trim().slice(0, 50),
          team: String(athlete.team || '').trim().slice(0, 50),
          grade: String(athlete.grade || '').trim().slice(0, 30),
          finishedAt: null,
        })).filter((athlete) => athlete.name),
      };
      if (event.athletes.length === 0) {
        sendJson(response, 400, { error: '選手名を入力してください' });
        return;
      }
      latestRace.events.push(event);
      saveRaces(latestRaces);
      broadcast(latestRace);
      sendJson(response, 201, { race: latestRace, event });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (request.method === 'POST' && (action === 'start' || action === 'finish')) {
    readBody(request).then((body) => {
      const latestRaces = readRaces();
      const latestRace = latestRaces[raceId];
      if (!latestRace) {
        sendJson(response, 404, { error: '大会が見つかりません' });
        return;
      }
      const event = latestRace.events.find((item) => item.id === body.eventId);
      if (!event) {
        sendJson(response, 404, { error: '競技が見つかりません' });
        return;
      }
      const clientTime = Number(body.clientTime);
      if (!Number.isFinite(clientTime) || clientTime < 0) {
        sendJson(response, 400, { error: '時刻を取得できませんでした' });
        return;
      }
      if (action === 'start') {
        if (event.startedAt) {
          sendJson(response, 409, { error: 'この組はすでにスタートしています' });
          return;
        }
        event.startedAt = clientTime;
        event.status = 'running';
      } else {
        const athlete = event.athletes.find((item) => item.id === body.athleteId);
        if (!athlete) {
          sendJson(response, 404, { error: '選手が見つかりません' });
          return;
        }
        if (!event.startedAt) {
          sendJson(response, 409, { error: '先にスタートを記録してください' });
          return;
        }
        if (athlete.finishedAt) {
          sendJson(response, 409, { error: 'この選手の記録は登録済みです' });
          return;
        }
        if (clientTime <= event.startedAt) {
          sendJson(response, 400, { error: 'フィニッシュ時刻がスタート時刻より前です' });
          return;
        }
        athlete.finishedAt = clientTime;
        if (event.athletes.every((item) => item.finishedAt)) event.status = 'complete';
      }
      saveRaces(latestRaces);
      broadcast(latestRace);
      sendJson(response, 200, { race: latestRace });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (request.method === 'GET' && !action) {
    sendJson(response, 200, publicRace(race));
    return;
  }

  sendJson(response, 405, { error: 'この操作には対応していません' });
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const user = currentUser(request);
  if (url.pathname === '/api/maintenance' && request.method === 'GET') {
    sendJson(response, 200, maintenanceSettings(readAccounts()));
    return;
  }
  const maintenance = url.pathname.startsWith('/api/')
    && (user?.role === 'organizer' || (url.pathname === '/api/auth/register' && request.method === 'POST'))
    ? maintenanceSettings(readAccounts())
    : { enabled: false, message: defaultMaintenanceMessage };
  const publicRaceRead = request.method === 'GET'
    && /^\/api\/races\/[A-Za-z0-9_-]{12}(?:\/(?:snapshot|stream))?$/.test(url.pathname);
  const allowedDuringMaintenance = ['/api/auth/me', '/api/auth/login', '/api/auth/logout', '/api/time'].includes(url.pathname)
    || publicRaceRead;
  if (maintenance.enabled && (
    (url.pathname === '/api/auth/register' && request.method === 'POST')
    || (user?.role === 'organizer' && !allowedDuringMaintenance)
  )) {
    request.resume();
    sendJson(response, 503, { error: maintenance.message, maintenance: true });
    return;
  }
  if (user?.mustChangePassword && !['/api/auth/me', '/api/auth/logout', '/api/auth/password/change'].includes(url.pathname)) {
    sendJson(response, 403, { error: '一時パスワードを変更してからご利用ください' });
    return;
  }

  if (url.pathname === '/api/auth/me' && request.method === 'GET') {
    sendJson(response, 200, { user });
    return;
  }

  if (url.pathname === '/api/auth/register' && request.method === 'POST') {
    readBody(request).then(async (body) => {
      const name = String(body.name || '').trim().slice(0, 60);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12) {
        sendJson(response, 400, { error: '名前、正しいメールアドレス、12文字以上のパスワードを入力してください' });
        return;
      }
      const accounts = readAccounts();
      if (accounts.users.some((item) => item.email === email)) {
        sendJson(response, 409, { error: 'このメールアドレスは登録済みです' });
        return;
      }
      const salt = crypto.randomBytes(16).toString('hex');
      const newUser = {
        id: crypto.randomUUID(),
        name,
        email,
        role: 'organizer',
        salt,
        passwordHash: await passwordHash(password, salt),
        createdAt: Date.now(),
      };
      accounts.users.push(newUser);
      createSession(request, response, newUser, accounts);
      sendJson(response, 201, { user: { id: newUser.id, name, email, role: newUser.role } });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (url.pathname === '/api/auth/login' && request.method === 'POST') {
    readBody(request).then(async (body) => {
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      const expectedRole = body.expectedRole;
      if (expectedRole !== undefined && !['organizer', 'admin'].includes(expectedRole)) {
        sendJson(response, 400, { error: 'ログイン画面の種別が正しくありません' });
        return;
      }
      const accounts = readAccounts();
      const foundUser = accounts.users.find((item) => item.email === email);
      if (!foundUser) {
        await passwordHash(password, crypto.randomBytes(16).toString('hex'));
        sendJson(response, 401, { error: 'メールアドレスまたはパスワードが違います' });
        return;
      }
      const actualHash = await passwordHash(password, foundUser.salt);
      const expected = Buffer.from(foundUser.passwordHash, 'hex');
      const actual = Buffer.from(actualHash, 'hex');
      if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
        sendJson(response, 401, { error: 'メールアドレスまたはパスワードが違います' });
        return;
      }
      if (expectedRole && foundUser.role !== expectedRole) {
        sendJson(response, 403, {
          error: expectedRole === 'admin'
            ? '管理者アカウントではありません。運営者ログインをご利用ください'
            : '運営者アカウントではありません。管理者ログインをご利用ください',
        });
        return;
      }
      createSession(request, response, foundUser, accounts);
      sendJson(response, 200, {
        user: {
          id: foundUser.id,
          name: foundUser.name,
          email,
          role: foundUser.role,
          mustChangePassword: Boolean(foundUser.mustChangePassword),
        },
      });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
    const token = cookieMap(request).sokuho_session;
    const accounts = readAccounts();
    if (token) delete accounts.sessions[crypto.createHash('sha256').update(token).digest('hex')];
    saveAccounts(accounts);
    response.setHeader('set-cookie', sessionCookie(request, '', 0));
    sendJson(response, 200, { ok: true });
    return;
  }

  if (url.pathname === '/api/auth/password/change' && request.method === 'POST') {
    if (user?.role !== 'organizer' || !user.mustChangePassword) {
      sendJson(response, user ? 403 : 401, { error: 'パスワード変更が必要な運営者のみ利用できます' });
      return;
    }
    readBody(request).then(async (body) => {
      const password = String(body.password || '');
      if (password.length < 12) {
        sendJson(response, 400, { error: '新しいパスワードは12文字以上にしてください' });
        return;
      }
      const accounts = readAccounts();
      const organizer = accounts.users.find((item) => item.id === user.id && item.role === 'organizer');
      const token = cookieMap(request).sokuho_session;
      const tokenHash = token && crypto.createHash('sha256').update(token).digest('hex');
      if (!organizer?.mustChangePassword || !accounts.sessions[tokenHash]) {
        sendJson(response, 401, { error: 'ログイン状態を確認できません。もう一度ログインしてください' });
        return;
      }
      organizer.salt = crypto.randomBytes(16).toString('hex');
      organizer.passwordHash = await passwordHash(password, organizer.salt);
      delete organizer.mustChangePassword;
      for (const [sessionId, session] of Object.entries(accounts.sessions)) {
        if (session.userId === organizer.id && sessionId !== tokenHash) delete accounts.sessions[sessionId];
      }
      saveAccounts(accounts);
      sendJson(response, 200, {
        user: { id: organizer.id, name: organizer.name, email: organizer.email, role: organizer.role, mustChangePassword: false },
      });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (url.pathname === '/api/organizer/portal' && request.method === 'GET') {
    if (user?.role !== 'organizer') {
      sendJson(response, user ? 403 : 401, { error: '運営者としてログインしてください' });
      return;
    }
    const accounts = readAccounts();
    sendJson(response, 200, {
      supportTickets: accounts.supportTickets
        .filter((ticket) => ticket.organizerId === user.id)
        .sort((left, right) => right.updatedAt - left.updatedAt),
      announcements: accounts.announcements
        .map((item) => ({ ...item, important: Boolean(item.important), seen: item.seenBy.includes(user.id) }))
        .sort((left, right) => right.createdAt - left.createdAt),
      venues: accounts.venues.map(venueDetails),
      countryCodes: UN_MEMBER_COUNTRY_CODES,
      venueRequests: accounts.venueRequests
        .filter((item) => item.organizerId === user.id)
        .sort((left, right) => right.updatedAt - left.updatedAt),
    });
    return;
  }

  if (url.pathname === '/api/organizer/venue-requests' && request.method === 'POST') {
    if (user?.role !== 'organizer') {
      sendJson(response, user ? 403 : 401, { error: '運営者としてログインしてください' });
      return;
    }
    readBody(request).then((body) => {
      const countryCode = String(body?.countryCode || '').toUpperCase();
      const name = typeof body?.name === 'string' ? body.name.trim().slice(0, 100) : '';
      const location = typeof body?.location === 'string' ? body.location.trim().slice(0, 150) : '';
      const website = typeof body?.website === 'string' ? body.website.trim().slice(0, 500) : '';
      const reason = typeof body?.reason === 'string' ? body.reason.trim().slice(0, 2000) : '';
      const raceId = typeof body?.raceId === 'string' ? body.raceId : '';
      if (!UN_MEMBER_COUNTRY_CODES.includes(countryCode) || !name || !location || reason.length < 20) {
        sendJson(response, 400, { error: '国、会場名、所在地、20文字以上の申請理由を入力してください' });
        return;
      }
      let parsedWebsite;
      try {
        parsedWebsite = new URL(website);
      } catch {
        sendJson(response, 400, { error: '会場の公式情報URLを入力してください' });
        return;
      }
      if (parsedWebsite.protocol !== 'https:' || !parsedWebsite.hostname || parsedWebsite.username || parsedWebsite.password) {
        sendJson(response, 400, { error: '公式情報URLには認証情報のないHTTPSアドレスを入力してください' });
        return;
      }
      const race = readRaces()[raceId];
      if (!race || !canManageRace(user, race)) {
        sendJson(response, 403, { error: '申請に紐づける担当大会を選択してください' });
        return;
      }
      const accounts = readAccounts();
      const venueIdentity = { countryCode, name, location };
      if (accounts.venues.some((venue) => matchesVenue(venue, venueIdentity))) {
        sendJson(response, 409, { error: 'この会場はすでに登録されています。大会作成フォームの候補から選択してください' });
        return;
      }
      if (accounts.venueRequests.some((item) => item.status === 'pending' && matchesVenue(item, venueIdentity))) {
        sendJson(response, 409, { error: '同じ会場の申請がすでに審査中です' });
        return;
      }
      const now = Date.now();
      const venueRequest = {
        id: crypto.randomUUID(),
        organizerId: user.id,
        raceId,
        raceTitle: race.title,
        countryCode,
        country: countryDisplayNames.of(countryCode),
        name,
        location,
        website: parsedWebsite.href,
        reason,
        status: 'pending',
        adminNote: '',
        createdAt: now,
        updatedAt: now,
      };
      accounts.venueRequests.push(venueRequest);
      saveAccounts(accounts);
      sendJson(response, 201, { venueRequest });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (url.pathname === '/api/support' && request.method === 'POST') {
    if (user?.role !== 'organizer') {
      sendJson(response, user ? 403 : 401, { error: 'お問い合わせには運営者ログインが必要です' });
      return;
    }
    readBody(request).then((body) => {
      const subject = String(body.subject || '').trim().slice(0, 120);
      const message = String(body.message || '').trim().slice(0, 3000);
      const type = body.type === 'password' ? 'password' : 'question';
      if (!subject || !message) {
        sendJson(response, 400, { error: '件名とお問い合わせ内容を入力してください' });
        return;
      }
      const accounts = readAccounts();
      const now = Date.now();
      const ticket = {
        id: crypto.randomUUID(),
        organizerId: user.id,
        type,
        subject,
        status: 'open',
        messages: [{ id: crypto.randomUUID(), senderId: user.id, senderRole: 'organizer', body: message, createdAt: now }],
        createdAt: now,
        updatedAt: now,
      };
      accounts.supportTickets.push(ticket);
      saveAccounts(accounts);
      sendJson(response, 201, { ticket });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  const supportMessageMatch = url.pathname.match(/^\/api\/support\/([0-9a-f-]{36})\/messages$/i);
  if (supportMessageMatch && request.method === 'POST') {
    if (!user || !['organizer', 'admin'].includes(user.role)) {
      sendJson(response, user ? 403 : 401, { error: 'ログインしてください' });
      return;
    }
    readBody(request).then((body) => {
      const message = String(body.message || '').trim().slice(0, 3000);
      if (!message) {
        sendJson(response, 400, { error: '返信内容を入力してください' });
        return;
      }
      const accounts = readAccounts();
      const ticket = accounts.supportTickets.find((item) => item.id === supportMessageMatch[1]);
      if (!ticket) {
        sendJson(response, 404, { error: 'お問い合わせが見つかりません' });
        return;
      }
      if (user.role === 'organizer' && ticket.organizerId !== user.id) {
        sendJson(response, 403, { error: 'このお問い合わせに返信する権限がありません' });
        return;
      }
      const now = Date.now();
      ticket.messages.push({ id: crypto.randomUUID(), senderId: user.id, senderRole: user.role, body: message, createdAt: now });
      ticket.updatedAt = now;
      ticket.status = user.role === 'admin' ? 'answered' : 'open';
      saveAccounts(accounts);
      sendJson(response, 200, { ticket });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  const announcementReadMatch = url.pathname.match(/^\/api\/organizer\/announcements\/([0-9a-f-]{36})\/read$/i);
  if (announcementReadMatch && request.method === 'POST') {
    if (user?.role !== 'organizer') {
      sendJson(response, user ? 403 : 401, { error: '運営者としてログインしてください' });
      return;
    }
    const accounts = readAccounts();
    const announcement = accounts.announcements.find((item) => item.id === announcementReadMatch[1]);
    if (!announcement) {
      sendJson(response, 404, { error: 'お知らせが見つかりません' });
      return;
    }
    if (!announcement.seenBy.includes(user.id)) announcement.seenBy.push(user.id);
    saveAccounts(accounts);
    sendJson(response, 200, { ok: true });
    return;
  }

  if (url.pathname === '/api/admin/summary' && request.method === 'GET') {
    if (user?.role !== 'admin') {
      sendJson(response, user ? 403 : 401, { error: '管理者専用です' });
      return;
    }
    const accounts = readAccounts();
    const organizers = accounts.users.filter((item) => item.role === 'organizer');
    const racesById = readRaces();
    const races = Object.values(racesById);
    const raceSummaries = races.map((race) => ({
      id: race.id,
      publicPath: `/r/${race.id}`,
      title: race.title,
      owner: accountLabel(accounts, race.ownerId),
      collaborators: groupDetails(race, accounts)?.members || [],
      createdAt: race.createdAt,
    }));
    sendJson(response, 200, {
      admin: accountLabel(accounts, user.id),
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
      races: raceSummaries,
      auditLog: accounts.auditLog.slice(-100).reverse().map((entry) => ({
        ...entry,
        actor: accountLabel(accounts, entry.actorId),
      })),
      supportTickets: accounts.supportTickets
        .map((ticket) => ({ ...ticket, organizer: accountLabel(accounts, ticket.organizerId) }))
        .sort((left, right) => right.updatedAt - left.updatedAt),
      announcements: accounts.announcements
        .map((item) => ({ ...item, important: Boolean(item.important) }))
        .sort((left, right) => right.createdAt - left.createdAt),
      venues: accounts.venues.map(venueDetails),
      countryCodes: UN_MEMBER_COUNTRY_CODES,
      venueRequests: accounts.venueRequests
        .map((item) => ({
          ...item,
          organizer: accountLabel(accounts, item.organizerId),
          raceTitle: racesById[item.raceId]?.title || item.raceTitle || '削除済み大会',
        }))
        .sort((left, right) => right.updatedAt - left.updatedAt),
      maintenance: maintenanceSettings(accounts),
    });
    return;
  }

  if (url.pathname === '/api/admin/maintenance' && request.method === 'POST') {
    if (user?.role !== 'admin') {
      sendJson(response, user ? 403 : 401, { error: '管理者専用です' });
      return;
    }
    readBody(request).then((body) => {
      if (typeof body?.enabled !== 'boolean') {
        sendJson(response, 400, { error: 'メンテナンス状態を指定してください' });
        return;
      }
      const message = typeof body.message === 'string' && body.message.trim()
        ? body.message.trim().slice(0, 500)
        : defaultMaintenanceMessage;
      const accounts = readAccounts();
      accounts.maintenance = { enabled: body.enabled, message };
      saveAccounts(accounts);
      sendJson(response, 200, { maintenance: maintenanceSettings(accounts) });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (url.pathname === '/api/admin/profile' && request.method === 'PATCH') {
    if (user?.role !== 'admin') {
      sendJson(response, user ? 403 : 401, { error: '管理者専用です' });
      return;
    }
    readBody(request).then((body) => {
      const name = typeof body?.name === 'string' ? body.name.trim().slice(0, 80) : '';
      if (!name) {
        sendJson(response, 400, { error: '管理者名を入力してください' });
        return;
      }
      const accounts = readAccounts();
      const admin = accounts.users.find((item) => item.id === user.id && item.role === 'admin');
      if (!admin) {
        sendJson(response, 404, { error: '管理者アカウントが見つかりません' });
        return;
      }
      admin.name = name;
      saveAccounts(accounts);
      sendJson(response, 200, { admin: accountLabel(accounts, admin.id) });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (url.pathname === '/api/admin/venues' && request.method === 'POST') {
    if (user?.role !== 'admin') {
      sendJson(response, user ? 403 : 401, { error: '管理者専用です' });
      return;
    }
    readBody(request).then((body) => {
      const countryCode = String(body?.countryCode || '').toUpperCase()
        || (body?.type === 'domestic' ? 'JP' : '');
      const name = typeof body?.name === 'string' ? body.name.trim().slice(0, 100) : '';
      const location = typeof body?.location === 'string' ? body.location.trim().slice(0, 150) : '';
      const address = typeof body?.address === 'string' ? body.address.trim().slice(0, 200) : '';
      if (!UN_MEMBER_COUNTRY_CODES.includes(countryCode) || !name) {
        sendJson(response, 400, { error: '国連加盟国と会場名を指定してください' });
        return;
      }
      const accounts = readAccounts();
      const venueIdentity = { countryCode, name, location };
      if (accounts.venues.some((item) => matchesVenue(item, venueIdentity))) {
        sendJson(response, 409, { error: '同じ国・所在地・会場名がすでに登録されています' });
        return;
      }
      const id = crypto.randomUUID();
      const venue = {
        id,
        sokuhoCode: venueCodeFor({ id }),
        ...venueIdentity,
        address,
        country: countryDisplayNames.of(countryCode),
        createdAt: Date.now(),
      };
      accounts.venues.push(venue);
      saveAccounts(accounts);
      sendJson(response, 201, { venue });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  const venueEditMatch = url.pathname.match(/^\/api\/admin\/venues\/([0-9a-f-]{36})$/i);
  if (venueEditMatch && request.method === 'PATCH') {
    if (user?.role !== 'admin') {
      sendJson(response, user ? 403 : 401, { error: '管理者専用です' });
      return;
    }
    readBody(request).then((body) => {
      const countryCode = String(body?.countryCode || '').toUpperCase();
      const name = typeof body?.name === 'string' ? body.name.trim().slice(0, 100) : '';
      const location = typeof body?.location === 'string' ? body.location.trim().slice(0, 150) : '';
      const address = typeof body?.address === 'string' ? body.address.trim().slice(0, 200) : '';
      if (!UN_MEMBER_COUNTRY_CODES.includes(countryCode) || !name) {
        sendJson(response, 400, { error: '国連加盟国と会場名を指定してください' });
        return;
      }
      const accounts = readAccounts();
      const venue = accounts.venues.find((item) => item.id === venueEditMatch[1]);
      if (!venue) {
        sendJson(response, 404, { error: '会場が見つかりません' });
        return;
      }
      const venueIdentity = { countryCode, name, location };
      if (accounts.venues.some((item) => item.id !== venue.id && matchesVenue(item, venueIdentity))) {
        sendJson(response, 409, { error: '同じ国・所在地・会場名がすでに登録されています' });
        return;
      }
      Object.assign(venue, venueIdentity, {
        address,
        country: countryDisplayNames.of(countryCode),
        sokuhoCode: venueCodeFor(venue),
        updatedAt: Date.now(),
      });
      saveAccounts(accounts);
      sendJson(response, 200, { venue: venueDetails(venue) });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  const venueRequestMatch = url.pathname.match(/^\/api\/admin\/venue-requests\/([0-9a-f-]{36})$/i);
  if (venueRequestMatch && request.method === 'PATCH') {
    if (user?.role !== 'admin') {
      sendJson(response, user ? 403 : 401, { error: '管理者専用です' });
      return;
    }
    readBody(request).then((body) => {
      const status = body?.status;
      const adminNote = typeof body?.adminNote === 'string' ? body.adminNote.trim().slice(0, 1000) : '';
      if (!['approved', 'rejected'].includes(status)) {
        sendJson(response, 400, { error: '審査結果を選択してください' });
        return;
      }
      if (status === 'rejected' && !adminNote) {
        sendJson(response, 400, { error: '却下理由を入力してください' });
        return;
      }
      const accounts = readAccounts();
      const venueRequest = accounts.venueRequests.find((item) => item.id === venueRequestMatch[1]);
      if (!venueRequest) {
        sendJson(response, 404, { error: '会場申請が見つかりません' });
        return;
      }
      if (venueRequest.status !== 'pending') {
        sendJson(response, 409, { error: 'この申請は審査済みです' });
        return;
      }
      let venue = accounts.venues.find((item) => matchesVenue(item, venueRequest));
      if (status === 'approved' && !venue) {
        const id = crypto.randomUUID();
        venue = {
          id,
          sokuhoCode: venueCodeFor({ id }),
          countryCode: venueRequest.countryCode,
          country: venueRequest.country,
          location: venueRequest.location,
          name: venueRequest.name,
          createdAt: Date.now(),
          sourceRequestId: venueRequest.id,
        };
        accounts.venues.push(venue);
      }
      venueRequest.status = status;
      venueRequest.adminNote = adminNote;
      venueRequest.reviewerId = user.id;
      venueRequest.venueId = venue?.id || null;
      venueRequest.updatedAt = Date.now();
      saveAccounts(accounts);
      sendJson(response, 200, { venueRequest, venue: venue || null });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (url.pathname === '/api/admin/announcements' && request.method === 'POST') {
    if (user?.role !== 'admin') {
      sendJson(response, user ? 403 : 401, { error: '管理者専用です' });
      return;
    }
    readBody(request).then((body) => {
      const title = String(body.title || '').trim().slice(0, 120);
      const message = String(body.message || '').trim().slice(0, 3000);
      if (!title || !message) {
        sendJson(response, 400, { error: '件名とお知らせ内容を入力してください' });
        return;
      }
      const accounts = readAccounts();
      const announcement = {
        id: crypto.randomUUID(),
        title,
        message,
        important: body.important === true,
        authorId: user.id,
        createdAt: Date.now(),
        seenBy: [],
      };
      accounts.announcements.push(announcement);
      saveAccounts(accounts);
      sendJson(response, 201, {
        announcement,
        recipientCount: accounts.users.filter((item) => item.role === 'organizer').length,
      });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  const supportStatusMatch = url.pathname.match(/^\/api\/admin\/support\/([0-9a-f-]{36})$/i);
  if (supportStatusMatch && request.method === 'PATCH') {
    if (user?.role !== 'admin') {
      sendJson(response, user ? 403 : 401, { error: '管理者専用です' });
      return;
    }
    readBody(request).then((body) => {
      if (!['open', 'answered', 'closed'].includes(body.status)) {
        sendJson(response, 400, { error: '対応状況の値が正しくありません' });
        return;
      }
      const accounts = readAccounts();
      const ticket = accounts.supportTickets.find((item) => item.id === supportStatusMatch[1]);
      if (!ticket) {
        sendJson(response, 404, { error: 'お問い合わせが見つかりません' });
        return;
      }
      ticket.status = body.status;
      ticket.updatedAt = Date.now();
      saveAccounts(accounts);
      sendJson(response, 200, { ticket });
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  const resetPasswordMatch = url.pathname.match(/^\/api\/admin\/organizers\/([0-9a-f-]{36})\/reset-password$/i);
  if (resetPasswordMatch && request.method === 'POST') {
    if (user?.role !== 'admin') {
      sendJson(response, user ? 403 : 401, { error: '管理者専用です' });
      return;
    }
    (async () => {
      const accounts = readAccounts();
      const organizer = accounts.users.find((item) => item.id === resetPasswordMatch[1] && item.role === 'organizer');
      if (!organizer) {
        sendJson(response, 404, { error: '運営者アカウントが見つかりません' });
        return;
      }
      const temporaryPassword = crypto.randomBytes(12).toString('hex');
      organizer.salt = crypto.randomBytes(16).toString('hex');
      organizer.passwordHash = await passwordHash(temporaryPassword, organizer.salt);
      organizer.mustChangePassword = true;
      for (const [sessionId, session] of Object.entries(accounts.sessions)) {
        if (session.userId === organizer.id) delete accounts.sessions[sessionId];
      }
      saveAccounts(accounts);
      sendJson(response, 200, { temporaryPassword });
    })().catch((error) => sendJson(response, 500, { error: error.message }));
    return;
  }

  if (url.pathname.startsWith('/api/admin/') && request.method === 'DELETE') {
    if (user?.role !== 'admin') {
      sendJson(response, user ? 403 : 401, { error: '管理者専用です' });
      return;
    }
    const venueMatch = url.pathname.match(/^\/api\/admin\/venues\/([0-9a-f-]{36})$/i);
    if (venueMatch) {
      const accounts = readAccounts();
      const venueIndex = accounts.venues.findIndex((venue) => venue.id === venueMatch[1]);
      if (venueIndex < 0) {
        sendJson(response, 404, { error: '会場が見つかりません' });
        return;
      }
      accounts.venues.splice(venueIndex, 1);
      saveAccounts(accounts);
      sendJson(response, 200, { ok: true });
      return;
    }
    const raceMatch = url.pathname.match(/^\/api\/admin\/races\/([A-Za-z0-9_-]{12})$/);
    if (raceMatch) {
      const races = readRaces();
      if (!races[raceMatch[1]]) {
        sendJson(response, 404, { error: '大会が見つかりません' });
        return;
      }
      closeDeletedRace(raceMatch[1]);
      delete races[raceMatch[1]];
      saveRaces(races);
      sendJson(response, 200, { ok: true });
      return;
    }

    const organizerMatch = url.pathname.match(/^\/api\/admin\/organizers\/([0-9a-f-]{36})$/i);
    if (organizerMatch) {
      const accounts = readAccounts();
      const organizer = accounts.users.find((item) => item.id === organizerMatch[1] && item.role === 'organizer');
      if (!organizer) {
        sendJson(response, 404, { error: '運営者アカウントが見つかりません' });
        return;
      }

      const races = readRaces();
      const organizerRaceIds = [];
      for (const race of Object.values(races)) {
        if (race.ownerId === organizer.id) {
          organizerRaceIds.push(race.id);
          closeDeletedRace(race.id);
          delete races[race.id];
        } else if (race.collaborationGroup?.memberIds.includes(organizer.id)) {
          race.collaborationGroup.memberIds = race.collaborationGroup.memberIds.filter((id) => id !== organizer.id);
          broadcast(race);
        }
      }
      saveRaces(races);
      accounts.users = accounts.users.filter((item) => item.id !== organizer.id);
      for (const [token, session] of Object.entries(accounts.sessions)) {
        if (session.userId === organizer.id) delete accounts.sessions[token];
      }
      saveAccounts(accounts);
      sendJson(response, 200, { ok: true, deletedRaces: organizerRaceIds.length });
      return;
    }

    sendJson(response, 404, { error: '削除対象が見つかりません' });
    return;
  }

  if (url.pathname === '/api/races' && request.method === 'GET') {
    if (user?.role !== 'organizer') {
      sendJson(response, user ? 403 : 401, { error: '運営者としてログインしてください' });
      return;
    }
    const accounts = readAccounts();
    const races = Object.values(readRaces()).filter((race) => canManageRace(user, race));
    sendJson(response, 200, races.map((race) => organizerRaceDetails(race, user, accounts)));
    return;
  }

  if (url.pathname === '/api/races' && request.method === 'POST') {
    readBody(request).then((body) => {
      if (user?.role !== 'organizer') {
        sendJson(response, user ? 403 : 401, { error: '大会作成には運営者ログインが必要です' });
        return;
      }
      const title = String(body.title || '').trim().slice(0, 80);
      if (!title) {
        sendJson(response, 400, { error: '大会名を入力してください' });
        return;
      }
      const races = readRaces();
      const id = crypto.randomBytes(9).toString('base64url');
      const race = {
        id,
        ownerId: user.id,
        collaborationGroup: null,
        title,
        date: String(body.date || '').slice(0, 10),
        venue: String(body.venue || '').trim().slice(0, 80),
        createdAt: Date.now(),
        events: [],
      };
      races[id] = race;
      saveRaces(races);
      sendJson(response, 201, race);
    }).catch((error) => sendJson(response, 400, { error: error.message }));
    return;
  }

  if (url.pathname === '/api/time' && request.method === 'GET') {
    sendJson(response, 200, { serverTime: Date.now() });
    return;
  }

  if (url.pathname.startsWith('/api/races/')) {
    routeRace(request, response, url, user, maintenance.enabled);
    return;
  }

  if ((/^\/r\/[A-Za-z0-9_-]{12}$/.test(url.pathname) || ['/admin', '/login'].includes(url.pathname)) && ['GET', 'HEAD'].includes(request.method)) {
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-cache',
    });
    if (request.method === 'HEAD') response.end();
    else fs.createReadStream(path.join(publicDir, 'index.html')).pipe(response);
    return;
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    sendJson(response, 405, { error: 'この操作には対応していません' });
    return;
  }

  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    sendJson(response, 400, { error: 'URLの形式が正しくありません' });
    return;
  }
  const filePath = path.resolve(publicDir, `.${pathname === '/' ? '/index.html' : pathname}`);
  if (!filePath.startsWith(`${publicDir}${path.sep}`)) {
    sendJson(response, 403, { error: 'アクセスできません' });
    return;
  }
  fs.readFile(filePath, (error, content) => {
    if (error) {
      sendJson(response, 404, { error: 'ページが見つかりません' });
      return;
    }
    const contentTypes = {
      '.html': 'text/html; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.png': 'image/png',
      '.gif': 'image/gif',
    };
    const contentType = contentTypes[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    response.writeHead(200, { 'content-type': contentType, 'cache-control': 'no-cache' });
    if (request.method === 'HEAD') response.end();
    else response.end(content);
  });
});

initializeAdmin().then(() => {
  server.listen(port, '0.0.0.0', () => {
    console.log(`Sokuho Result is running at http://localhost:${port}`);
  });
}).catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});