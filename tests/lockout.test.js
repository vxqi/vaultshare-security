const request = require('supertest');
const { createTestApp, cleanupTestApp, extractCsrf } = require('./helpers/setupTestApp');

// Isolated in its own file/app instance since it deliberately exhausts the
// login rate limiter's attempt budget - keeping it separate means it can't
// starve other test files of login attempts.
describe('Account lockout', () => {
  let app, db, tmpRoot, agent;

  beforeAll(async () => {
    ({ app, db, tmpRoot } = createTestApp('lockout'));
    agent = request.agent(app);

    const page = await agent.get('/register');
    const csrf = extractCsrf(page.text);
    await agent.post('/register').type('form').send({
      _csrf: csrf,
      displayName: 'Carol Target',
      email: 'carol@example.com',
      password: 'Sup3r!SecurePass01',
      confirmPassword: 'Sup3r!SecurePass01',
    });
  });

  afterAll(() => cleanupTestApp(tmpRoot, db));

  test('account locks after 5 failed attempts and returns 423', async () => {
    const attemptAgent = request.agent(app);
    let lastRes;

    // The 5th failed attempt is the one that SETS the lock in the DB, but
    // that same request still responds 401 (the lock check at the top of
    // the handler reads the user record as it was at the start of the
    // request, before this attempt's update). The lock only takes visible
    // effect starting on the NEXT request - hence 6 attempts here, not 5.
    for (let i = 0; i < 6; i++) {
      const page = await attemptAgent.get('/login');
      const csrf = extractCsrf(page.text);
      lastRes = await attemptAgent.post('/login').type('form').send({
        _csrf: csrf, email: 'carol@example.com', password: `WrongPassword${i}!`,
      });
    }

    expect(lastRes.status).toBe(423);
    expect(lastRes.text).toContain('locked');
  });

  test('correct password is still rejected while locked', async () => {
    const attemptAgent = request.agent(app);
    const page = await attemptAgent.get('/login');
    const csrf = extractCsrf(page.text);
    const res = await attemptAgent.post('/login').type('form').send({
      _csrf: csrf, email: 'carol@example.com', password: 'Sup3r!SecurePass01',
    });
    expect(res.status).toBe(423);
  });
});