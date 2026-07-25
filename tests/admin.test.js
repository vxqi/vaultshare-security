const request = require('supertest');
const { createTestApp, cleanupTestApp, extractCsrf } = require('./helpers/setupTestApp');

async function registerAndLogin(app, { displayName, email, password }) {
  const agent = request.agent(app);
  const regPage = await agent.get('/register');
  await agent.post('/register').type('form').send({
    _csrf: extractCsrf(regPage.text), displayName, email, password, confirmPassword: password,
  });
  const loginPage = await agent.get('/login');
  await agent.post('/login').type('form').send({
    _csrf: extractCsrf(loginPage.text), email, password,
  });
  return agent;
}

describe('Admin RBAC', () => {
  let app, db, tmpRoot, admin, user;

  beforeAll(async () => {
    ({ app, db, tmpRoot } = createTestApp('admin'));
    // First registered account bootstraps to admin.
    admin = await registerAndLogin(app, { displayName: 'Admin One', email: 'admin@example.com', password: 'Str0ng!Passw0rd99' });
    user = await registerAndLogin(app, { displayName: 'Regular User', email: 'user@example.com', password: 'An0ther!Str0ngPass77' });
  });

  afterAll(() => cleanupTestApp(tmpRoot, db));

  test('a regular user is blocked from every admin route', async () => {
    const usersRes = await user.get('/admin/users');
    expect(usersRes.status).toBe(403);

    const activityRes = await user.get('/admin/activity');
    expect(activityRes.status).toBe(403);
  });

  test('the admin can view the user list and activity log', async () => {
    const usersRes = await admin.get('/admin/users');
    expect(usersRes.status).toBe(200);
    expect(usersRes.text).toContain('Regular User');

    const activityRes = await admin.get('/admin/activity');
    expect(activityRes.status).toBe(200);
  });

  test('admin can disable another user, and that user is immediately blocked from logging in', async () => {
    const usersPage = await admin.get('/admin/users');
    const csrf = extractCsrf(usersPage.text);
    const disableRes = await admin.post('/admin/users/2/toggle-active').type('form').send({ _csrf: csrf });
    expect(disableRes.status).toBe(302);

    const freshAgent = request.agent(app);
    const loginPage = await freshAgent.get('/login');
    const loginCsrf = extractCsrf(loginPage.text);
    const loginRes = await freshAgent.post('/login').type('form').send({
      _csrf: loginCsrf, email: 'user@example.com', password: 'An0ther!Str0ngPass77',
    });
    expect(loginRes.status).toBe(403);
    expect(loginRes.text).toContain('disabled');
  });

  test('admin cannot disable their own account', async () => {
    const usersPage = await admin.get('/admin/users');
    const csrf = extractCsrf(usersPage.text);
    const res = await admin.post('/admin/users/1/toggle-active').type('form').send({ _csrf: csrf });
    expect(res.status).toBe(400);
  });

  test('admin cannot change their own role', async () => {
    const usersPage = await admin.get('/admin/users');
    const csrf = extractCsrf(usersPage.text);
    const res = await admin.post('/admin/users/1/role').type('form').send({ _csrf: csrf, role: 'user' });
    expect(res.status).toBe(400);
  });
});