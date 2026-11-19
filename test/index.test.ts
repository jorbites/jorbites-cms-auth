import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { sanitizeScope } from '../src/index.ts';

const baseEnv = {
    GITHUB_CLIENT_ID: 'client-id-123',
    GITHUB_CLIENT_SECRET: 'client-secret-456',
    ALLOWED_ORIGIN: 'https://jorbites.github.io',
};

test('sanitizeScope allows only allowlisted scopes and falls back to public_repo', () => {
    assert.equal(sanitizeScope(null), 'public_repo');
    assert.equal(sanitizeScope('repo'), 'repo');
    assert.equal(sanitizeScope('public_repo read:user'), 'public_repo read:user');
    assert.equal(sanitizeScope('delete_repo admin:org'), 'public_repo');
    assert.equal(sanitizeScope('repo,delete_repo,user:email'), 'repo user:email');
});

test('GET /auth restricts requested GitHub OAuth scope and sets HttpOnly Secure state cookie', async () => {
    const req = new Request(
        'https://cms-auth.example.workers.dev/auth?scope=delete_repo'
    );
    const res = await worker.fetch(req, baseEnv);

    assert.equal(res.status, 302);
    const location = new URL(res.headers.get('Location')!);
    assert.equal(location.searchParams.get('scope'), 'public_repo');
    assert.equal(location.searchParams.get('client_id'), 'client-id-123');
    const cookie = res.headers.get('Set-Cookie') || '';
    assert.match(cookie, /oauth_state=[0-9a-f-]+; HttpOnly; Secure; SameSite=Lax; Path=\/callback/);
});

test('GET /callback enforces exact allowedOrigin (no *.github.io wildcard) and escapes script tags', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
        new Response(
            JSON.stringify({
                error: 'bad_verification_code',
                error_description: "</script><script>alert('xss')</script>",
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
        )) as typeof fetch;

    try {
        const req = new Request(
            'https://cms-auth.example.workers.dev/callback?code=abc&state=state-1',
            { headers: { Cookie: 'oauth_state=state-1' } }
        );
        const res = await worker.fetch(req, baseEnv);
        const html = await res.text();

        assert.equal(res.status, 200);
        assert.equal(res.headers.get('Cache-Control'), 'no-store');
        assert.match(res.headers.get('Set-Cookie') || '', /Max-Age=0/);
        assert.doesNotMatch(html, /endsWith\(['"]\.github\.io['"]\)/);
        assert.doesNotMatch(html, /postMessage\('authorizing:github',\s*'\*'\)/);
        assert.match(html, /if \(e\.origin !== allowedOrigin\)/);
        assert.doesNotMatch(html, /<\/script><script>alert/);
        assert.match(html, /\\u003c\/script\\u003e/);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('GET /callback rejects invalid CSRF state token and clears cookie', async () => {
    const req = new Request(
        'https://cms-auth.example.workers.dev/callback?code=abc&state=wrong',
        { headers: { Cookie: 'oauth_state=expected' } }
    );
    const res = await worker.fetch(req, baseEnv);
    const html = await res.text();

    assert.equal(res.status, 200);
    assert.match(html, /Invalid or expired CSRF state token/);
    assert.match(res.headers.get('Set-Cookie') || '', /Max-Age=0/);
});

test('wildcard ALLOWED_ORIGIN falls back to default https://jorbites.github.io', async () => {
    const req = new Request('https://cms-auth.example.workers.dev/health');
    const res = await worker.fetch(req, { ...baseEnv, ALLOWED_ORIGIN: '*' });

    assert.equal(
        res.headers.get('Access-Control-Allow-Origin'),
        'https://jorbites.github.io'
    );
});
