import assert from 'node:assert/strict';

const issuer = 'https://example.supabase.co';
const user = { id: 'fake-user', user_metadata: { display_name: 'Drawing Tester' } };
const jwt = (expiresIn, stage) => [
  Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
  Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + expiresIn, stage })).toString('base64url'),
  'fixture',
].join('.');

const initialAccessToken = jwt(3600, 'initial');
const refreshedAccessToken = jwt(3600, 'refreshed');
const originalFetch = globalThis.fetch;

globalThis.fetch = async (input, init) => {
  const url = new URL(input instanceof Request ? input.url : input);
  if (url.origin !== issuer) return originalFetch(input, init);

  const request = new Request(input, init);
  if (url.pathname === '/auth/v1/oauth/token') {
    assert.equal(request.method, 'POST');
    assert.match(request.headers.get('content-type'), /^application\/x-www-form-urlencoded/);
    const form = new URLSearchParams(await request.text());
    assert.equal(form.get('client_id'), 'drawing-chat-ci-client');
    if (form.get('grant_type') === 'authorization_code') {
      assert.equal(form.get('code'), 'fixture-code');
      assert.match(form.get('code_verifier'), /^[\w-]{43}$/);
      assert.equal(form.get('redirect_uri'), 'http://127.0.0.1:3167/api/drawing-id/callback');
      return Response.json({ access_token: initialAccessToken, refresh_token: 'initial-refresh', expires_in: 3600 });
    }

    assert.equal(form.get('grant_type'), 'refresh_token');
    assert.equal(form.get('refresh_token'), 'initial-refresh');
    return Response.json({ access_token: refreshedAccessToken, refresh_token: 'rotated-refresh', expires_in: 3600 });
  }

  if (url.pathname === '/auth/v1/user') {
    assert.equal(request.method, 'GET');
    const token = request.headers.get('authorization');
    assert.ok([initialAccessToken, refreshedAccessToken].some(value => token === `Bearer ${value}`));
    return Response.json(user);
  }

  if (url.pathname === '/auth/v1/logout') {
    assert.equal(request.method, 'POST');
    assert.equal(url.searchParams.get('scope'), 'local');
    assert.equal(request.headers.get('authorization'), `Bearer ${refreshedAccessToken}`);
    return Response.json({ message: 'OAuth client tokens are not allowed on this endpoint' }, { status: 403 });
  }

  throw new Error(`Unexpected fixture request: ${request.method} ${url.pathname}`);
};
