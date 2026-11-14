import assert from 'node:assert/strict';
import test from 'node:test';

test('a changed deployment secret resets the existing admin password', async () => {
  const { default: initialBackend } = await import('./backend.mjs?admin-password-initial');
  const { default: updatedBackend } = await import('./backend.mjs?admin-password-updated');
  let version = 0;
  let state = { races: {}, accounts: { users: [], sessions: {} } };
  const DB = {
    async load() {
      return { version, state: structuredClone(state) };
    },
    async compareAndSwap(expectedVersion, nextState) {
      if (expectedVersion !== version) return false;
      state = structuredClone(nextState);
      version += 1;
      return true;
    },
  };
  const makeEnv = (password) => ({ DB, ADMIN_EMAIL: 'admin@example.com', ADMIN_PASSWORD: password });
  const request = (backend, env, path, body) => backend.fetch(new Request(`https://example.test${path}`, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  }), env);

  const firstLoginPage = await request(initialBackend, makeEnv('initial-password-123'), '/api/auth/me');
  assert.equal(firstLoginPage.status, 200);
  const firstLogin = await request(initialBackend, makeEnv('initial-password-123'), '/api/auth/login', {
    email: 'admin@example.com',
    password: 'initial-password-123',
  });
  assert.equal(firstLogin.status, 200);
  assert.equal(Object.keys(state.accounts.sessions).length, 1);

  const updatedLoginPage = await request(updatedBackend, makeEnv('replacement-password-456'), '/api/auth/me');
  assert.equal(updatedLoginPage.status, 200);
  assert.equal(Object.keys(state.accounts.sessions).length, 0);

  const oldPasswordLogin = await request(updatedBackend, makeEnv('replacement-password-456'), '/api/auth/login', {
    email: 'admin@example.com',
    password: 'initial-password-123',
  });
  assert.equal(oldPasswordLogin.status, 401);

  const newPasswordLogin = await request(updatedBackend, makeEnv('replacement-password-456'), '/api/auth/login', {
    email: 'admin@example.com',
    password: 'replacement-password-456',
  });
  assert.equal(newPasswordLogin.status, 200);
});

test('login rejects credentials that do not match the selected account type', async () => {
  const { default: backend } = await import('./backend.mjs?auth-role-mismatch');
  let version = 0;
  let state = { races: {}, accounts: { users: [], sessions: {} } };
  const DB = {
    async load() {
      return { version, state: structuredClone(state) };
    },
    async compareAndSwap(expectedVersion, nextState) {
      if (expectedVersion !== version) return false;
      state = structuredClone(nextState);
      version += 1;
      return true;
    },
  };
  const env = { DB, ADMIN_EMAIL: 'admin@example.com', ADMIN_PASSWORD: 'admin-password-123' };
  const request = (path, body) => backend.fetch(new Request(`https://example.test${path}`, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  }), env);

  await request('/api/auth/me');
  const registration = await request('/api/auth/register', {
    name: '運営者',
    email: 'organizer@example.com',
    password: 'organizer-password-123',
  });
  assert.equal(registration.status, 201);
  const initialSessionCount = Object.keys(state.accounts.sessions).length;

  const adminFromOrganizerLogin = await request('/api/auth/login', {
    email: env.ADMIN_EMAIL,
    password: env.ADMIN_PASSWORD,
    expectedRole: 'organizer',
  });
  assert.equal(adminFromOrganizerLogin.status, 403);
  assert.match((await adminFromOrganizerLogin.json()).error, /運営者アカウントではありません/);

  const organizerFromAdminLogin = await request('/api/auth/login', {
    email: 'organizer@example.com',
    password: 'organizer-password-123',
    expectedRole: 'admin',
  });
  assert.equal(organizerFromAdminLogin.status, 403);
  assert.match((await organizerFromAdminLogin.json()).error, /管理者アカウントではありません/);
  assert.equal(Object.keys(state.accounts.sessions).length, initialSessionCount);

  assert.equal((await request('/api/auth/login', {
    email: env.ADMIN_EMAIL,
    password: env.ADMIN_PASSWORD,
    expectedRole: 'unknown',
  })).status, 400);
});

test('organizers can request help and change a temporary password, while admins can reply and broadcast', async () => {
  const { default: backend } = await import('./backend.mjs?organizer-support');
  let version = 0;
  let state = { races: {}, accounts: { users: [], sessions: {} } };
  const DB = {
    async load() {
      return { version, state: structuredClone(state) };
    },
    async compareAndSwap(expectedVersion, nextState) {
      if (expectedVersion !== version) return false;
      state = structuredClone(nextState);
      version += 1;
      return true;
    },
  };
  const env = { DB, ADMIN_EMAIL: 'admin@example.com', ADMIN_PASSWORD: 'admin-password-123' };
  const request = async (path, body, session, method = body ? 'POST' : 'GET') => backend.fetch(new Request(`https://example.test${path}`, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(session ? { 'x-sokuho-session': session } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  }), env);
  const json = async (response) => response.json();

  await request('/api/auth/me');
  const adminLogin = await request('/api/auth/login', {
    email: env.ADMIN_EMAIL,
    password: env.ADMIN_PASSWORD,
  });
  const adminSession = adminLogin.headers.get('x-sokuho-session');
  const registration = await request('/api/auth/register', {
    name: '運営者',
    email: 'organizer@example.com',
    password: 'organizer-password-123',
  });
  const organizer = await json(registration);
  const organizerId = organizer.user.id;
  const organizerSession = registration.headers.get('x-sokuho-session');

  const ticketResponse = await request('/api/support', {
    type: 'password',
    subject: 'パスワード変更依頼',
    message: 'パスワード変更をお願いします。',
  }, organizerSession);
  const ticket = (await json(ticketResponse)).ticket;
  assert.equal(ticketResponse.status, 201);
  assert.equal((await request('/api/admin/summary', undefined, organizerSession)).status, 403);

  const replyResponse = await request(`/api/support/${ticket.id}/messages`, {
    message: '本人確認後、一時パスワードを発行します。',
  }, adminSession);
  assert.equal(replyResponse.status, 200);
  assert.equal((await json(replyResponse)).ticket.status, 'answered');

  const resetResponse = await request(`/api/admin/organizers/${organizerId}/reset-password`, {}, adminSession);
  const { temporaryPassword } = await json(resetResponse);
  assert.equal(resetResponse.status, 200);
  assert.equal(temporaryPassword.length, 24);
  assert.equal((await json(await request('/api/auth/me', undefined, organizerSession))).user, null);
  assert.equal((await request('/api/auth/login', {
    email: 'organizer@example.com',
    password: 'organizer-password-123',
  })).status, 401);

  const temporaryLogin = await request('/api/auth/login', {
    email: 'organizer@example.com',
    password: temporaryPassword,
  });
  const temporarySession = temporaryLogin.headers.get('x-sokuho-session');
  assert.equal((await json(temporaryLogin)).user.mustChangePassword, true);
  assert.equal((await request('/api/races', undefined, temporarySession)).status, 403);

  const passwordChange = await request('/api/auth/password/change', {
    password: 'organizer-password-new-456',
  }, temporarySession);
  assert.equal(passwordChange.status, 200);
  assert.equal((await json(await request('/api/auth/me', undefined, temporarySession))).user.mustChangePassword, false);
  assert.equal((await request('/api/auth/login', {
    email: 'organizer@example.com',
    password: temporaryPassword,
  })).status, 401);
  assert.equal((await request('/api/auth/login', {
    email: 'organizer@example.com',
    password: 'organizer-password-new-456',
  })).status, 200);

  const raceResponse = await request('/api/races', {
    title: '公開テスト大会',
    date: '2026-11-13',
  }, temporarySession);
  const race = await json(raceResponse);
  assert.equal(raceResponse.status, 201);
  const publicSnapshot = await json(await request(`/api/races/${race.id}/snapshot`));
  assert.equal(publicSnapshot.race.id, race.id);
  assert.deepEqual(publicSnapshot.access, { canManage: false, isOwner: false, isCollaborator: false });
  assert.equal(publicSnapshot.group, null);
  const addEvent = await request(`/api/races/${race.id}/events`, {
    name: '男子100m',
    scheduledAt: 1763020000000,
    athletes: [{ name: 'テスト選手', team: '青葉中', grade: '中2' }],
  }, temporarySession);
  assert.equal(addEvent.status, 201);
  const firstEvent = (await json(addEvent)).event;
  assert.equal(firstEvent.athletes[0].grade, '中2');
  assert.equal(firstEvent.scheduledAt, 1763020000000);
  assert.equal((await request(`/api/races/${race.id}/events/${firstEvent.id}`, {
    name: '記録を修正',
    round: '決勝',
    startedAt: null,
    scheduledAt: null,
    athletes: firstEvent.athletes.map((athlete) => ({ ...athlete, grade: '中3', finishedAt: null })),
  }, undefined, 'PATCH')).status, 401);
  const start = await request(`/api/races/${race.id}/start`, {
    eventId: firstEvent.id,
    clientTime: 1000,
  }, temporarySession);
  assert.equal(start.status, 200);
  const finish = await request(`/api/races/${race.id}/finish`, {
    eventId: firstEvent.id,
    athleteId: firstEvent.athletes[0].id,
    clientTime: 61000,
  }, temporarySession);
  assert.equal(finish.status, 200);
  const updateEvent = await request(`/api/races/${race.id}/events/${firstEvent.id}`, {
    name: '男子100m 決勝',
    round: '決勝',
    startedAt: 1000,
    scheduledAt: 1763020000000,
    athletes: [{ ...firstEvent.athletes[0], grade: '中3', finishedAt: 62000 }],
  }, temporarySession, 'PATCH');
  assert.equal(updateEvent.status, 200);
  const updatedEvent = (await json(updateEvent)).event;
  assert.equal(updatedEvent.athletes[0].finishedAt, 62000);
  assert.equal(updatedEvent.athletes[0].grade, '中3');
  const invalidCorrection = await request(`/api/races/${race.id}/events/${firstEvent.id}`, {
    name: '不正な記録',
    round: '決勝',
    startedAt: 1000,
    scheduledAt: null,
    athletes: [{ ...updatedEvent.athletes[0], finishedAt: 1000 }],
  }, temporarySession, 'PATCH');
  assert.equal(invalidCorrection.status, 400);
  assert.equal(state.races[race.id].events[0].athletes[0].finishedAt, 62000);
  const addSecondEvent = await request(`/api/races/${race.id}/events`, {
    name: '女子100m',
    athletes: [{ name: '別の選手', team: '港中', grade: '中1' }],
  }, temporarySession);
  const secondEvent = (await json(addSecondEvent)).event;
  const reordered = await request(`/api/races/${race.id}/events/order`, {
    eventIds: [secondEvent.id, firstEvent.id],
  }, temporarySession, 'PATCH');
  assert.equal(reordered.status, 200);
  assert.deepEqual((await json(reordered)).race.events.map((item) => item.id), [secondEvent.id, firstEvent.id]);
  assert.equal(state.auditLog.length, 2);
  const publicRaceAfterUpdate = await json(await request(`/api/races/${race.id}`));
  assert.equal(publicRaceAfterUpdate.id, race.id);
  assert.equal(publicRaceAfterUpdate.events[1].name, '男子100m 決勝');
  assert.equal(publicRaceAfterUpdate.events[1].athletes[0].grade, '中3');

  const announcement = await request('/api/admin/announcements', {
    title: 'アップデートのお知らせ',
    message: '新機能を追加しました。',
    important: true,
  }, adminSession);
  assert.equal(announcement.status, 201);
  const adminSummary = await json(await request('/api/admin/summary', undefined, adminSession));
  assert.equal(adminSummary.races[0].publicPath, `/r/${race.id}`);
  assert.equal(adminSummary.auditLog[0].action, 'event_order_changed');
  assert.equal(adminSummary.auditLog[0].actor.id, organizerId);
  assert.equal(adminSummary.auditLog[1].action, 'event_updated');
  const portal = await json(await request('/api/organizer/portal', undefined, temporarySession));
  assert.equal(portal.supportTickets.length, 1);
  assert.equal(portal.supportTickets[0].messages.at(-1).senderRole, 'admin');
  assert.equal(portal.announcements[0].seen, false);
  assert.equal(portal.announcements[0].important, true);
  const readResponse = await request(`/api/organizer/announcements/${portal.announcements[0].id}/read`, {}, temporarySession);
  assert.equal(readResponse.status, 200);
  const updatedPortal = await json(await request('/api/organizer/portal', undefined, temporarySession));
  assert.equal(updatedPortal.announcements[0].seen, true);

  const closedTicket = await request(`/api/admin/support/${ticket.id}`, { status: 'closed' }, adminSession, 'PATCH');
  assert.equal(closedTicket.status, 200);
  assert.equal((await json(await request('/api/organizer/portal', undefined, temporarySession))).supportTickets[0].status, 'closed');
});

test('admins can manage UN-member country venues and review organizer venue requests', async () => {
  const { default: backend } = await import('./backend.mjs?admin-venue-catalog');
  let version = 0;
  let state = { races: {}, accounts: { users: [], sessions: {} } };
  const DB = {
    async load() {
      return { version, state: structuredClone(state) };
    },
    async compareAndSwap(expectedVersion, nextState) {
      if (expectedVersion !== version) return false;
      state = structuredClone(nextState);
      version += 1;
      return true;
    },
  };
  const env = { DB, ADMIN_EMAIL: 'admin@example.com', ADMIN_PASSWORD: 'admin-password-123' };
  const request = async (path, body, session, method = body ? 'POST' : 'GET') => backend.fetch(new Request(`https://example.test${path}`, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(session ? { 'x-sokuho-session': session } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  }), env);
  const json = async (response) => response.json();

  await request('/api/auth/me');
  const adminLogin = await request('/api/auth/login', {
    email: env.ADMIN_EMAIL,
    password: env.ADMIN_PASSWORD,
  });
  const adminSession = adminLogin.headers.get('x-sokuho-session');
  const registration = await request('/api/auth/register', {
    name: '運営者',
    email: 'venue-organizer@example.com',
    password: 'organizer-password-123',
  });
  const organizerSession = registration.headers.get('x-sokuho-session');

  assert.equal((await request('/api/admin/venues', { countryCode: 'JP', location: '東京都', name: '国立競技場' })).status, 401);
  assert.equal((await request('/api/admin/venues', { countryCode: 'JP', location: '東京都', name: '国立競技場' }, organizerSession)).status, 403);
  assert.equal((await request('/api/admin/venues', { countryCode: 'VA', location: '東京都', name: '国立競技場' }, adminSession)).status, 400);

  const domesticResponse = await request('/api/admin/venues', {
    countryCode: 'JP',
    location: '東京都',
    name: '国立競技場',
  }, adminSession);
  const domesticVenue = (await json(domesticResponse)).venue;
  assert.equal(domesticResponse.status, 201);
  assert.equal(domesticVenue.countryCode, 'JP');
  const internationalResponse = await request('/api/admin/venues', {
    countryCode: 'US',
    location: 'アメリカ・カリフォルニア州',
    name: 'Example Stadium',
  }, adminSession);
  assert.equal(internationalResponse.status, 201);

  const portal = await json(await request('/api/organizer/portal', undefined, organizerSession));
  assert.equal(portal.countryCodes.length, 193);
  assert.deepEqual(portal.venues.map(({ countryCode, location, name }) => ({ countryCode, location, name })), [
    { countryCode: 'JP', location: '東京都', name: '国立競技場' },
    { countryCode: 'US', location: 'アメリカ・カリフォルニア州', name: 'Example Stadium' },
  ]);
  assert.equal((await request(`/api/admin/venues/${domesticVenue.id}`, undefined, organizerSession, 'DELETE')).status, 403);
  assert.equal((await request(`/api/admin/venues/${domesticVenue.id}`, undefined, adminSession, 'DELETE')).status, 200);
  const raceResponse = await request('/api/races', {
    title: '申請テスト大会',
    date: '2026-11-13',
  }, organizerSession);
  const race = await json(raceResponse);
  assert.equal(raceResponse.status, 201);

  const requestDetails = {
    raceId: race.id,
    countryCode: 'JP',
    location: '大阪府大阪市',
    name: '申請会場',
    website: 'https://example.jp/venue',
    reason: 'この大会の会場として利用予定のため登録を申請します。',
  };
  assert.equal((await request('/api/organizer/venue-requests', requestDetails)).status, 401);
  assert.equal((await request('/api/organizer/venue-requests', { ...requestDetails, website: 'http://example.jp' }, organizerSession)).status, 400);
  const venueRequestResponse = await request('/api/organizer/venue-requests', requestDetails, organizerSession);
  const venueRequest = (await json(venueRequestResponse)).venueRequest;
  assert.equal(venueRequestResponse.status, 201);
  assert.equal(venueRequest.raceId, race.id);
  assert.equal((await request('/api/organizer/venue-requests', requestDetails, organizerSession)).status, 409);

  const adminSummary = await json(await request('/api/admin/summary', undefined, adminSession));
  assert.equal(adminSummary.countryCodes.length, 193);
  assert.equal(adminSummary.venueRequests[0].organizer.email, 'venue-organizer@example.com');
  assert.equal(adminSummary.venueRequests[0].raceTitle, '申請テスト大会');
  assert.equal((await request(`/api/admin/venue-requests/${venueRequest.id}`, { status: 'approved' }, organizerSession, 'PATCH')).status, 403);
  assert.equal((await request(`/api/admin/venue-requests/${venueRequest.id}`, { status: 'approved' }, adminSession, 'PATCH')).status, 200);
  assert.equal((await request(`/api/admin/venue-requests/${venueRequest.id}`, { status: 'approved' }, adminSession, 'PATCH')).status, 409);

  const organizerPortal = await json(await request('/api/organizer/portal', undefined, organizerSession));
  assert.equal(organizerPortal.venueRequests[0].status, 'approved');
  const summary = await json(await request('/api/admin/summary', undefined, adminSession));
  assert.deepEqual(summary.venues.map((venue) => venue.name), ['Example Stadium', '申請会場']);

  const rejectedRequestResponse = await request('/api/organizer/venue-requests', {
    ...requestDetails,
    location: '北海道札幌市',
    name: '却下テスト会場',
  }, organizerSession);
  const rejectedRequest = (await json(rejectedRequestResponse)).venueRequest;
  assert.equal(rejectedRequestResponse.status, 201);
  assert.equal((await request(`/api/admin/venue-requests/${rejectedRequest.id}`, {
    status: 'rejected',
  }, adminSession, 'PATCH')).status, 400);
  assert.equal((await request(`/api/admin/venue-requests/${rejectedRequest.id}`, {
    status: 'rejected',
    adminNote: '公式情報を確認できませんでした。',
  }, adminSession, 'PATCH')).status, 200);
});

test('maintenance blocks organizer APIs while preserving public race access and admin controls', async () => {
  const { default: backend } = await import('./backend.mjs?maintenance-mode');
  let version = 0;
  let state = { races: {}, accounts: { users: [], sessions: {} } };
  const DB = {
    async load() {
      return { version, state: structuredClone(state) };
    },
    async compareAndSwap(expectedVersion, nextState) {
      if (expectedVersion !== version) return false;
      state = structuredClone(nextState);
      version += 1;
      return true;
    },
  };
  const env = { DB, ADMIN_EMAIL: 'admin@example.com', ADMIN_PASSWORD: 'admin-password-123' };
  const request = async (path, body, session, method = body ? 'POST' : 'GET') => backend.fetch(new Request(`https://example.test${path}`, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(session ? { 'x-sokuho-session': session } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  }), env);
  const json = async (response) => response.json();

  await request('/api/auth/me');
  const adminLogin = await request('/api/auth/login', {
    email: env.ADMIN_EMAIL,
    password: env.ADMIN_PASSWORD,
  });
  const adminSession = adminLogin.headers.get('x-sokuho-session');
  const registration = await request('/api/auth/register', {
    name: '運営者',
    email: 'maintenance-organizer@example.com',
    password: 'organizer-password-123',
  });
  const organizerSession = registration.headers.get('x-sokuho-session');
  const createdRace = await request('/api/races', {
    title: '公開中の大会',
    date: '2026-11-13',
  }, organizerSession);
  const race = await json(createdRace);
  assert.equal(createdRace.status, 201);

  assert.equal((await request('/api/admin/maintenance', { enabled: true }, organizerSession)).status, 403);
  const enable = await request('/api/admin/maintenance', {
    enabled: true,
    message: 'メンテナンス中です。復旧までお待ちください。',
  }, adminSession);
  assert.equal(enable.status, 200);
  assert.deepEqual(await json(await request('/api/maintenance')), {
    enabled: true,
    message: 'メンテナンス中です。復旧までお待ちください。',
  });
  assert.equal((await request('/api/organizer/portal', undefined, organizerSession)).status, 503);
  assert.equal((await request('/api/races', undefined, organizerSession)).status, 503);
  assert.equal((await request('/api/races', { title: '停止中の大会' }, organizerSession)).status, 503);
  assert.equal((await request(`/api/races/${race.id}/events`, { name: '男子100m', athletes: [{ name: '選手' }] }, organizerSession)).status, 503);
  assert.equal((await request('/api/auth/register', {
    name: '別の運営者',
    email: 'blocked-organizer@example.com',
    password: 'organizer-password-123',
  })).status, 503);

  const publicRace = await json(await request(`/api/races/${race.id}`));
  assert.equal(publicRace.id, race.id);
  const publicSnapshot = await json(await request(`/api/races/${race.id}/snapshot`, undefined, organizerSession));
  assert.deepEqual(publicSnapshot.access, { canManage: false, isOwner: true, isCollaborator: false });
  assert.equal(publicSnapshot.group, null);
  assert.equal((await request('/api/admin/summary', undefined, adminSession)).status, 200);

  const disable = await request('/api/admin/maintenance', { enabled: false, message: '作業中です' }, adminSession);
  assert.equal(disable.status, 200);
  assert.equal((await json(await request('/api/maintenance'))).enabled, false);
  assert.equal((await request('/api/races', undefined, organizerSession)).status, 200);
});
