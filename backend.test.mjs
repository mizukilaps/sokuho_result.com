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
    athletes: [{ name: 'テスト選手' }],
  }, temporarySession);
  assert.equal(addEvent.status, 201);
  const publicRaceAfterUpdate = await json(await request(`/api/races/${race.id}`));
  assert.equal(publicRaceAfterUpdate.id, race.id);
  assert.equal(publicRaceAfterUpdate.events[0].name, '男子100m');

  const announcement = await request('/api/admin/announcements', {
    title: 'アップデートのお知らせ',
    message: '新機能を追加しました。',
    important: true,
  }, adminSession);
  assert.equal(announcement.status, 201);
  const adminSummary = await json(await request('/api/admin/summary', undefined, adminSession));
  assert.equal(adminSummary.races[0].publicPath, `/r/${race.id}`);
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
