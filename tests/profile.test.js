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

describe('Profile: mass assignment defense and discovery boundaries', () => {
  let app, db, tmpRoot, alice, bob;

  beforeAll(async () => {
    ({ app, db, tmpRoot } = createTestApp('profile'));
    alice = await registerAndLogin(app, { displayName: 'Alice Owner', email: 'alice@example.com', password: 'Str0ng!Passw0rd99' });
    bob = await registerAndLogin(app, { displayName: 'Bob Client', email: 'bob@example.com', password: 'An0ther!Str0ngPass77' });
  });

  afterAll(() => cleanupTestApp(tmpRoot, db));

  test('legitimate profile fields save correctly', async () => {
    const profilePage = await bob.get('/profile');
    const csrf = extractCsrf(profilePage.text);
    const res = await bob.post('/profile').type('form').send({
      _csrf: csrf, bio: 'A freelance illustrator', companyName: 'Bob Studio',
      website: 'https://bob.example.com', avatarColor: '#4FB286',
    });
    expect(res.status).toBe(302);

    const updated = await bob.get('/profile');
    expect(updated.text).toContain('A freelance illustrator');
  });

  test('attempting to inject role/id/email via the profile endpoint is silently ignored', async () => {
    const profilePage = await bob.get('/profile');
    const csrf = extractCsrf(profilePage.text);

    await bob.post('/profile').type('form').send({
      _csrf: csrf, bio: 'still bob', companyName: 'x', website: '', avatarColor: '#4FB286',
      role: 'admin', email: 'hacked@evil.com', id: 1, is_active: 0, mfa_enabled: 0,
    });

    // Bob must still be a regular user and blocked from the admin panel.
    const adminRes = await bob.get('/admin/users');
    expect(adminRes.status).toBe(403);
  });

  test('avatar upload rejects disallowed file types', async () => {
    const profilePage = await bob.get('/profile');
    const csrf = extractCsrf(profilePage.text);
    const res = await bob.post('/profile/avatar')
      .field('_csrf', csrf)
      .attach('avatar', Buffer.from('not an image'), { filename: 'evil.txt', contentType: 'text/plain' });
    expect(res.status).toBe(400);
    expect(res.text).toContain('must be a PNG');
  });

  test('avatar upload accepts a valid PNG and serves it to any authenticated user', async () => {
    // Minimal valid 1x1 PNG
    const pngBuffer = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
      'base64'
    );
    const profilePage = await bob.get('/profile');
    const csrf = extractCsrf(profilePage.text);
    const uploadRes = await bob.post('/profile/avatar')
      .field('_csrf', csrf)
      .attach('avatar', pngBuffer, { filename: 'me.png', contentType: 'image/png' });
    expect(uploadRes.status).toBe(302);

    const profileAfter = await bob.get('/profile');
    const match = profileAfter.text.match(/\/avatars\/([a-f0-9-]{36})/);
    expect(match).toBeTruthy();

    const avatarRes = await alice.get(`/avatars/${match[1]}`);
    expect(avatarRes.status).toBe(200);
    expect(avatarRes.headers['content-type']).toBe('image/png');
  });

  test('public profile is discoverable without any prior relationship, but shows no private files', async () => {
    // Alice uploads one private and one public file.
    const uploadPage = await alice.get('/files/upload');
    const csrf1 = extractCsrf(uploadPage.text);
    await alice.post('/files/upload').field('_csrf', csrf1)
      .attach('file', Buffer.from('secret'), { filename: 'secret.txt', contentType: 'text/plain' });

    const uploadPage2 = await alice.get('/files/upload');
    const csrf2 = extractCsrf(uploadPage2.text);
    await alice.post('/files/upload').field('_csrf', csrf2).field('isPublic', 'on')
      .attach('file', Buffer.from('showcase'), { filename: 'showcase.txt', contentType: 'text/plain' });

    // A brand-new user with zero relationship to Alice.
    const carol = await registerAndLogin(app, { displayName: 'Carol Newcomer', email: 'carol@example.com', password: 'An0ther!Pass02' });

    const aliceProfile = await carol.get('/users/1/profile');
    expect(aliceProfile.status).toBe(200);
    expect(aliceProfile.text).toContain('showcase.txt');
    expect(aliceProfile.text).not.toContain('secret.txt');
  });

  test('search matches by name, but never by email', async () => {
    const byName = await bob.get('/users/search?q=Alice');
    expect(byName.text).toContain('Alice Owner');

    const byEmail = await bob.get('/users/search?q=alice@example.com');
    expect(byEmail.text).not.toContain('Alice Owner');
  });
});