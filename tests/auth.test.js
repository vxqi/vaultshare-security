const request = require('supertest');
const { createTestApp, cleanupTestApp, extractCsrf } = require('./helpers/setupTestApp');

describe('Registration and login', () => {
  let app, db, tmpRoot, agent;

  beforeAll(() => {
    ({ app, db, tmpRoot } = createTestApp('auth'));
    agent = request.agent(app);
  });

  afterAll(() => cleanupTestApp(tmpRoot, db));

  test('GET /register renders the registration form', async () => {
    const res = await agent.get('/register');
    expect(res.status).toBe(200);
    expect(res.text).toContain('_csrf');
  });

  test('registering with a weak password is rejected', async () => {
    const page = await agent.get('/register');
    const csrf = extractCsrf(page.text);

    const res = await agent.post('/register').type('form').send({
      _csrf: csrf,
      displayName: 'Weak Pw User',
      email: 'weak@example.com',
      password: 'short',
      confirmPassword: 'short',
    });

    expect(res.status).toBe(400);
    // Account should NOT have been created
    const loginPage = await agent.get('/login');
    const loginCsrf = extractCsrf(loginPage.text);
    const loginRes = await agent.post('/login').type('form').send({
      _csrf: loginCsrf, email: 'weak@example.com', password: 'short',
    });
    expect(loginRes.status).toBe(401);
  });

  test('registering with a strong password succeeds and becomes admin (first account bootstrap)', async () => {
    const page = await agent.get('/register');
    const csrf = extractCsrf(page.text);

    const res = await agent.post('/register').type('form').send({
      _csrf: csrf,
      displayName: 'Alice Admin',
      email: 'alice@example.com',
      password: 'Str0ng!Passw0rd99',
      confirmPassword: 'Str0ng!Passw0rd99',
    });

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login?registered=1');
  });

  test('second registration becomes a regular user, not admin', async () => {
    const page = await agent.get('/register');
    const csrf = extractCsrf(page.text);

    await agent.post('/register').type('form').send({
      _csrf: csrf,
      displayName: 'Bob Client',
      email: 'bob@example.com',
      password: 'An0ther!Str0ngPass77',
      confirmPassword: 'An0ther!Str0ngPass77',
    });

    // Log in as Bob and confirm he can't reach the admin panel.
    const loginPage = await agent.get('/login');
    const loginCsrf = extractCsrf(loginPage.text);
    await agent.post('/login').type('form').send({
      _csrf: loginCsrf, email: 'bob@example.com', password: 'An0ther!Str0ngPass77',
    });

    const adminRes = await agent.get('/admin/users');
    expect(adminRes.status).toBe(403);
  });

  test('login with wrong password is rejected with a generic error', async () => {
    const freshAgent = request.agent(app);
    const page = await freshAgent.get('/login');
    const csrf = extractCsrf(page.text);

    const res = await freshAgent.post('/login').type('form').send({
      _csrf: csrf, email: 'alice@example.com', password: 'TotallyWrongPassword1!',
    });

    expect(res.status).toBe(401);
    expect(res.text).toContain('Invalid email or password');
  });

  test('login with correct password succeeds and reaches the dashboard', async () => {
    const freshAgent = request.agent(app);
    const page = await freshAgent.get('/login');
    const csrf = extractCsrf(page.text);

    const res = await freshAgent.post('/login').type('form').send({
      _csrf: csrf, email: 'alice@example.com', password: 'Str0ng!Passw0rd99',
    });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/dashboard');

    const dash = await freshAgent.get('/dashboard');
    expect(dash.status).toBe(200);
    expect(dash.text).toContain('Your files');
  });

  test('a request with no CSRF token is rejected', async () => {
    const freshAgent = request.agent(app);
    await freshAgent.get('/login'); // establish a session/cookie
    const res = await freshAgent.post('/login').type('form').send({
      email: 'alice@example.com', password: 'Str0ng!Passw0rd99',
    });
    expect(res.status).toBe(403);
  });
});