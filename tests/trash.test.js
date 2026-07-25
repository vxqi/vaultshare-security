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

describe('Recycle bin', () => {
  let app, db, tmpRoot, alice, bob, fileUuid;

  beforeAll(async () => {
    ({ app, db, tmpRoot } = createTestApp('trash'));
    alice = await registerAndLogin(app, { displayName: 'Alice Owner', email: 'alice@example.com', password: 'Str0ng!Passw0rd99' });
    bob = await registerAndLogin(app, { displayName: 'Bob Client', email: 'bob@example.com', password: 'An0ther!Str0ngPass77' });

    const uploadPage = await alice.get('/files/upload');
    const csrf = extractCsrf(uploadPage.text);
    await alice.post('/files/upload').field('_csrf', csrf)
      .attach('file', Buffer.from('doc contents'), { filename: 'doc.txt', contentType: 'text/plain' });

    const dash = await alice.get('/dashboard');
    fileUuid = dash.text.match(/\/files\/([a-f0-9-]{36})\/download/)[1];
  });

  afterAll(() => cleanupTestApp(tmpRoot, db));

  test('deleting a file removes it from the dashboard and puts it in trash', async () => {
    const dash = await alice.get('/dashboard');
    const csrf = extractCsrf(dash.text);
    const delRes = await alice.post(`/files/${fileUuid}/delete`).type('form').send({ _csrf: csrf });
    expect(delRes.status).toBe(302);

    const dashAfter = await alice.get('/dashboard');
    expect(dashAfter.text).not.toContain('doc.txt');

    const trash = await alice.get('/dashboard/trash');
    expect(trash.status).toBe(200);
    expect(trash.text).toContain('doc.txt');
  });

  test('a non-owner cannot restore or purge a trashed file', async () => {
    // Get Bob a genuinely valid CSRF token for his own session first, so
    // this test actually exercises the ownership check (404) rather than
    // failing earlier on an unrelated CSRF mismatch.
    const bobPage = await bob.get('/dashboard');
    const bobCsrf = extractCsrf(bobPage.text);

    const restoreRes = await bob.post(`/files/${fileUuid}/restore`).type('form').send({ _csrf: bobCsrf });
    expect(restoreRes.status).toBe(404);

    const purgeRes = await bob.post(`/files/${fileUuid}/purge`).type('form').send({ _csrf: bobCsrf });
    expect(purgeRes.status).toBe(404);
  });

  test('the owner can restore the file and it reappears on the dashboard', async () => {
    const trash = await alice.get('/dashboard/trash');
    const csrf = extractCsrf(trash.text);
    const res = await alice.post(`/files/${fileUuid}/restore`).type('form').send({ _csrf: csrf });
    expect(res.status).toBe(302);

    const dash = await alice.get('/dashboard');
    expect(dash.text).toContain('doc.txt');
  });

  test('purging a file permanently removes it and it no longer appears in trash', async () => {
    // Delete then purge.
    const dash = await alice.get('/dashboard');
    const csrf1 = extractCsrf(dash.text);
    await alice.post(`/files/${fileUuid}/delete`).type('form').send({ _csrf: csrf1 });

    const trash = await alice.get('/dashboard/trash');
    const csrf2 = extractCsrf(trash.text);
    const purgeRes = await alice.post(`/files/${fileUuid}/purge`).type('form').send({ _csrf: csrf2 });
    expect(purgeRes.status).toBe(302);

    const trashAfter = await alice.get('/dashboard/trash');
    expect(trashAfter.text).not.toContain('doc.txt');

    // And it should be genuinely gone, not just hidden - downloading should 404.
    const downloadRes = await alice.get(`/files/${fileUuid}/download`);
    expect(downloadRes.status).toBe(404);
  });

  test('deleting a folder cascades to soft-delete the files inside it', async () => {
    const dash = await alice.get('/dashboard');
    const csrf = extractCsrf(dash.text);
    await alice.post('/files/folders').type('form').send({ _csrf: csrf, name: 'Contracts' });

    const dash2 = await alice.get('/dashboard');
    const folderId = dash2.text.match(/folder=(\d+)/)[1];

    const uploadPage = await alice.get(`/files/upload?folder=${folderId}`);
    const uploadCsrf = extractCsrf(uploadPage.text);
    await alice.post('/files/upload').field('_csrf', uploadCsrf).field('folderId', folderId)
      .attach('file', Buffer.from('nested'), { filename: 'nested.txt', contentType: 'text/plain' });

    const folderView = await alice.get(`/dashboard?folder=${folderId}`);
    const folderCsrf = extractCsrf(folderView.text);
    const delRes = await alice.post(`/files/folders/${folderId}/delete`).type('form').send({ _csrf: folderCsrf });
    expect(delRes.status).toBe(302);

    const trash = await alice.get('/dashboard/trash');
    expect(trash.text).toContain('Contracts');
    expect(trash.text).toContain('nested.txt');
  });
});