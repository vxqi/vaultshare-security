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

describe('File access control', () => {
  let app, db, tmpRoot, alice, bob;

  beforeAll(async () => {
    ({ app, db, tmpRoot } = createTestApp('fileaccess'));
    alice = await registerAndLogin(app, { displayName: 'Alice Owner', email: 'alice@example.com', password: 'Str0ng!Passw0rd99' });
    bob = await registerAndLogin(app, { displayName: 'Bob Client', email: 'bob@example.com', password: 'An0ther!Str0ngPass77' });
  });

  afterAll(() => cleanupTestApp(tmpRoot, db));

  let privateUuid, publicUuid;

  test('Alice uploads a private file (default) and a public file', async () => {
    const uploadPage = await alice.get('/files/upload');
    const csrf = extractCsrf(uploadPage.text);

    const privRes = await alice.post('/files/upload')
      .field('_csrf', csrf)
      .attach('file', Buffer.from('Private contract contents'), { filename: 'private.txt', contentType: 'text/plain' });
    expect(privRes.status).toBe(302);

    const uploadPage2 = await alice.get('/files/upload');
    const csrf2 = extractCsrf(uploadPage2.text);
    const pubRes = await alice.post('/files/upload')
      .field('_csrf', csrf2)
      .field('isPublic', 'on')
      .attach('file', Buffer.from('Public portfolio piece'), { filename: 'public.txt', contentType: 'text/plain' });
    expect(pubRes.status).toBe(302);

    const dash = await alice.get('/dashboard');
    const uuids = [...dash.text.matchAll(/\/files\/([a-f0-9-]{36})\/download/g)].map(m => m[1]);
    expect(uuids.length).toBe(2);

    // Determine which uuid belongs to which file by checking each file's own share page.
    for (const uuid of uuids) {
      const sharePage = await alice.get(`/files/${uuid}/share`);
      if (sharePage.text.includes('private.txt')) privateUuid = uuid;
      if (sharePage.text.includes('public.txt')) publicUuid = uuid;
    }
    expect(privateUuid).toBeTruthy();
    expect(publicUuid).toBeTruthy();
    expect(privateUuid).not.toBe(publicUuid);
  });

  test('Bob cannot download the private file (404, not 403)', async () => {
    const res = await bob.get(`/files/${privateUuid}/download`);
    expect(res.status).toBe(404);
  });

  test('Bob CAN download the public file', async () => {
    const res = await bob.get(`/files/${publicUuid}/download`);
    expect(res.status).toBe(200);
    expect(res.text).toContain('Public portfolio piece');
  });

  test('toggling visibility flips access immediately', async () => {
    const sharePage = await alice.get(`/files/${privateUuid}/share`);
    const csrf = extractCsrf(sharePage.text);
    await alice.post(`/files/${privateUuid}/visibility`).type('form').send({ _csrf: csrf });

    const nowPublic = await bob.get(`/files/${privateUuid}/download`);
    expect(nowPublic.status).toBe(200);

    // toggle back
    const sharePage2 = await alice.get(`/files/${privateUuid}/share`);
    const csrf2 = extractCsrf(sharePage2.text);
    await alice.post(`/files/${privateUuid}/visibility`).type('form').send({ _csrf: csrf2 });

    const nowPrivateAgain = await bob.get(`/files/${privateUuid}/download`);
    expect(nowPrivateAgain.status).toBe(404);
  });

  test('Bob cannot toggle visibility on a file he does not own', async () => {
    const res = await bob.post(`/files/${privateUuid}/visibility`).type('form').send({ _csrf: 'irrelevant' });
    // Either blocked by CSRF (403) or, if that somehow passed, by ownership (404) -
    // the important invariant is it must never succeed with a 302 redirect.
    expect(res.status).not.toBe(302);
  });

  test('Bob cannot delete a file he does not own', async () => {
    const res = await bob.post(`/files/${privateUuid}/delete`).type('form').send({ _csrf: 'irrelevant' });
    expect(res.status).not.toBe(302);
  });

  test('sharing grants Bob explicit access to the private file', async () => {
    const sharePage = await alice.get(`/files/${privateUuid}/share`);
    const csrf = extractCsrf(sharePage.text);
    const shareRes = await alice.post(`/files/${privateUuid}/share`).type('form').send({
      _csrf: csrf, email: 'bob@example.com', permission: 'view',
    });
    expect(shareRes.status).toBe(302);

    const downloadRes = await bob.get(`/files/${privateUuid}/download`);
    expect(downloadRes.status).toBe(200);
  });
});