/**
 * Sveltia CMS / Decap CMS GitHub OAuth Provider for Cloudflare Workers
 * Repository: jorbites/events-cms-auth
 */

export interface Env {
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
    ALLOWED_ORIGIN?: string; // e.g. "https://jorbites.github.io"
}

const DEFAULT_ALLOWED_ORIGIN = 'https://jorbites.github.io';
const ALLOWED_SCOPES = new Set(['public_repo', 'repo', 'read:user', 'user:email']);

export function sanitizeScope(rawScope: string | null): string {
    if (!rawScope) {
        return 'public_repo';
    }
    const validScopes = rawScope
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter((s) => ALLOWED_SCOPES.has(s));
    return validScopes.length > 0 ? Array.from(new Set(validScopes)).join(' ') : 'public_repo';
}

function serializeForScript(value: unknown): string {
    return JSON.stringify(value)
        .replace(/</g, '\\u003c')
        .replace(/>/g, '\\u003e')
        .replace(/&/g, '\\u0026')
        .replace(/\u2028/g, '\\u2028')
        .replace(/\u2029/g, '\\u2029');
}

function timingSafeEqualString(a: string, b: string): boolean {
    const encoder = new TextEncoder();
    const aBytes = encoder.encode(a);
    const bBytes = encoder.encode(b);
    if (aBytes.length !== bBytes.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < aBytes.length; i++) {
        diff |= aBytes[i] ^ bBytes[i];
    }
    return diff === 0;
}

function resolveAllowedOrigin(configured?: string): string {
    const candidate = (configured || DEFAULT_ALLOWED_ORIGIN).trim();
    try {
        const parsed = new URL(candidate);
        if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost') {
            return DEFAULT_ALLOWED_ORIGIN;
        }
        return parsed.origin;
    } catch {
        return DEFAULT_ALLOWED_ORIGIN;
    }
}

function createCorsHeaders(allowedOrigin: string): HeadersInit {
    return {
        'Access-Control-Allow-Origin': allowedOrigin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        Vary: 'Origin',
    };
}

function renderHtmlResponse(
    status: 'success' | 'error',
    payload: Record<string, unknown>,
    allowedOrigin: string,
    extraHeaders?: Record<string, string>
): Response {
    const serializedAllowedOrigin = serializeForScript(allowedOrigin);
    const serializedStatus = serializeForScript(status);
    const serializedPayloadJson = serializeForScript(JSON.stringify(payload));
    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Authorizing Jorbites CMS</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      background: #f7fafc;
      color: #2d3748;
    }
    .card {
      background: #fff;
      padding: 2rem;
      border-radius: 8px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.05);
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="card">
    <h2>Connecting to GitHub...</h2>
    <p>This window will close automatically once authentication completes.</p>
  </div>
  <script>
    (function() {
      const allowedOrigin = ${serializedAllowedOrigin};
      const status = ${serializedStatus};
      const payloadJson = ${serializedPayloadJson};
      function receiveMessage(e) {
        if (e.origin !== allowedOrigin) {
          console.warn('Rejected postMessage from untrusted origin:', e.origin);
          return;
        }
        if (window.opener) {
          window.opener.postMessage(
            'authorization:github:' + status + ':' + payloadJson,
            allowedOrigin
          );
        }
        window.close();
      }
      window.addEventListener('message', receiveMessage, false);
      if (window.opener) {
        window.opener.postMessage('authorizing:github', allowedOrigin);
      }
    })();
  </script>
</body>
</html>`;

    return new Response(html, {
        headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            ...createCorsHeaders(allowedOrigin),
            ...(extraHeaders || {}),
        },
    });
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);
        const allowedOrigin = resolveAllowedOrigin(env.ALLOWED_ORIGIN);

        // Handle CORS preflight
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                status: 204,
                headers: createCorsHeaders(allowedOrigin),
            });
        }

        // Health check endpoint
        if (url.pathname === '/' || url.pathname === '/health') {
            return new Response(
                JSON.stringify({ status: 'ok', service: 'jorbites-cms-auth' }),
                {
                    headers: {
                        'Content-Type': 'application/json',
                        ...createCorsHeaders(allowedOrigin),
                    },
                }
            );
        }

        // 1. Step 1: Initiate OAuth (/auth)
        if (url.pathname === '/auth') {
            if (!env.GITHUB_CLIENT_ID) {
                return new Response('Missing GITHUB_CLIENT_ID', { status: 500 });
            }

            const scope = sanitizeScope(url.searchParams.get('scope'));
            // Generate secure random state token
            const state = crypto.randomUUID();

            const redirectUri = `${url.origin}/callback`;
            const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
            githubAuthUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
            githubAuthUrl.searchParams.set('redirect_uri', redirectUri);
            githubAuthUrl.searchParams.set('scope', scope);
            githubAuthUrl.searchParams.set('state', state);

            // Store state in a short-lived secure cookie for CSRF validation
            const headers = new Headers();
            headers.set('Location', githubAuthUrl.toString());
            headers.append(
                'Set-Cookie',
                `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/callback; Max-Age=300`
            );

            return new Response(null, {
                status: 302,
                headers,
            });
        }

        // 2. Step 2: Handle OAuth Callback (/callback)
        if (url.pathname === '/callback') {
            const code = url.searchParams.get('code');
            const state = url.searchParams.get('state');

            // Verify state cookie for CSRF protection
            const cookieHeader = request.headers.get('Cookie') || '';
            const cookies = Object.fromEntries(
                cookieHeader.split(';').map((c) => {
                    const [k, ...v] = c.trim().split('=');
                    return [k, v.join('=')];
                })
            );
            const expectedState = cookies['oauth_state'];

            const clearStateCookie = {
                'Set-Cookie':
                    'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/callback; Max-Age=0',
            };

            if (!code) {
                return renderHtmlResponse(
                    'error',
                    { error: 'Missing authorization code from GitHub' },
                    allowedOrigin,
                    clearStateCookie
                );
            }

            if (
                !state ||
                !expectedState ||
                !timingSafeEqualString(state, expectedState)
            ) {
                return renderHtmlResponse(
                    'error',
                    {
                        error: 'Invalid or expired CSRF state token. Please try logging in again.',
                    },
                    allowedOrigin,
                    clearStateCookie
                );
            }

            if (!env.GITHUB_CLIENT_SECRET) {
                return renderHtmlResponse(
                    'error',
                    {
                        error: 'Server configuration error: Missing GITHUB_CLIENT_SECRET',
                    },
                    allowedOrigin,
                    clearStateCookie
                );
            }

            try {
                // Exchange temporary code for access token
                const tokenResponse = await fetch(
                    'https://github.com/login/oauth/access_token',
                    {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            Accept: 'application/json',
                            'User-Agent': 'jorbites-cms-auth',
                        },
                        body: JSON.stringify({
                            client_id: env.GITHUB_CLIENT_ID,
                            client_secret: env.GITHUB_CLIENT_SECRET,
                            code,
                        }),
                    }
                );

                const data = (await tokenResponse.json()) as {
                    access_token?: string;
                    error?: string;
                    error_description?: string;
                };

                if (data.error || !data.access_token) {
                    const errorMessage =
                        data.error_description || data.error || 'Failed to exchange token with GitHub';
                    return renderHtmlResponse(
                        'error',
                        { error: errorMessage },
                        allowedOrigin,
                        clearStateCookie
                    );
                }

                // Successful authentication
                return renderHtmlResponse(
                    'success',
                    { token: data.access_token, provider: 'github' },
                    allowedOrigin,
                    clearStateCookie
                );
            } catch (err: unknown) {
                const message = err instanceof Error ? err.message : 'Unknown error during token exchange';
                return renderHtmlResponse(
                    'error',
                    { error: message },
                    allowedOrigin,
                    clearStateCookie
                );
            }
        }

        return new Response('Not Found', {
            status: 404,
            headers: createCorsHeaders(allowedOrigin),
        });
    },
};
