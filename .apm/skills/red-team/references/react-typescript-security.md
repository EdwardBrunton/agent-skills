# React / TypeScript Security Reference

Stack notes for TS/TSX/JS scopes: React SPAs, Next.js/Remix, and Node services. Sections
are headed with the persona they belong to; each agent reads only its own, alongside
its language-agnostic brief.

---

## Authentication & Authorisation (`authz-agent`)

- **Client-side gating is UI, not authorisation.** A route guard, `if (user.isAdmin)`
  render check, or hidden menu item protects nothing; the finding is the *server* endpoint
  it calls lacking its own check. Report the client gate only as the pointer to that
  endpoint.
- **Token storage.** Access/refresh tokens in `localStorage`/`sessionStorage` are readable
  by any XSS; prefer `HttpOnly` cookies or in-memory with a silent refresh. A token
  persisted to `localStorage` is a finding when an XSS sink exists anywhere in the app.
- **MSAL / OIDC config.** `redirectUri` built from `window.location` without an allow-list;
  `navigateToLoginRequestUrl` with an unvalidated return path; `validateAuthority: false`
  (MSAL v1) or `knownAuthorities` widened beyond the tenant's own authority (v2+);
  scopes requested far wider than used.
- **Server-side (Next.js/Remix/Express).** API routes, server actions, `loader`/`action`
  functions, and middleware that read the session but skip the authorisation decision;
  `middleware.ts` matchers that leave a route unmatched; a server action callable with
  another user's id in the form data.
- **JWT on Node.** `jsonwebtoken.verify` with `algorithms` unset (algorithm confusion),
  `jwt.decode` used where `verify` was meant, missing `audience`/`issuer`, `ignoreExpiration`.
- **Express middleware order.** Auth middleware registered after the route, or applied to
  `app.use('/api')` while a sibling router mounts outside the prefix.

## Injection (`injection-agent`)

- **XSS sinks.** `dangerouslySetInnerHTML`, `innerHTML`/`outerHTML`, `document.write`,
  `insertAdjacentHTML`, `eval`/`new Function`, `setTimeout(string)`. React escapes JSX
  text by default — report only where that is bypassed.
- **URL-context XSS.** User data into `href`, `src`, `action`, `formAction`, or
  `window.open` without a scheme allow-list — `javascript:` and `data:` URLs pass React's
  escaping untouched.
- **Sanitiser bypass.** `DOMPurify` with a custom `ALLOWED_TAGS`/`ADD_ATTR` that readmits
  `style`, `svg`, `iframe`, or event handlers; sanitising on the server then re-rendering
  via a client sink that re-parses.
- **Markdown and rich text.** `react-markdown` with `rehype-raw`, `marked` without
  sanitisation, Quill/TinyMCE output rendered raw.
- **Server-side rendering.** Serialising state into `<script>` tags
  (`JSON.stringify(state)` inside `__NEXT_DATA__`-style bootstraps) without escaping
  `</script>` and `<!--`; `serialize-javascript` absent.
- **Node sinks.** `child_process.exec`/`execSync` with a composed string (prefer
  `execFile` with an array); `fs` paths from input without `path.resolve` plus a
  `startsWith(baseDir)` check; template engines with `escape: false`; `vm.runInContext`
  on input.
- **SQL/NoSQL on Node.** Template literals into `knex.raw`, `sequelize.query`, `pg`
  `client.query`; Mongo queries that pass a request object straight in (`{ $gt: "" }`
  operator injection), `$where`.
- **Prototype pollution.** Deep-merge/`Object.assign` of request bodies into config or
  defaults; `lodash.merge`/`set` with user-controlled keys; `__proto__`/`constructor` not
  rejected.
- **SSRF on Node.** `fetch`/`axios` with a user URL; redirects followed by default;
  `0.0.0.0`, `[::]`, decimal/octal IPs, and the cloud metadata endpoint bypassing a
  hostname allow-list.
- **ReDoS.** A regex with nested quantifiers applied to unbounded user input, especially
  in validators.

## Secrets & Cryptography (`secrets-crypto-agent`)

- **Bundled secrets.** Anything in `VITE_*`, `NEXT_PUBLIC_*`, `REACT_APP_*`, or imported
  into client code ships to every browser; a server-only key in one of these is a
  disclosure. Also `.env`/`.env.local` committed, secrets in `vite.config.ts`/
  `next.config.js`, or in `public/`.
- **Source maps in production** exposing server-side logic or comments containing
  credentials.
- **`Math.random()`** for tokens, ids, nonces, or CSRF values — require
  `crypto.getRandomValues`/`crypto.randomUUID` (browser) or `crypto.randomBytes` (Node).
- **Node crypto.** `createCipher` (deprecated, no IV), `md5`/`sha1` for security, a
  static IV, `crypto.timingSafeEqual` absent on token comparison, `bcrypt`/`argon2`
  absent for password storage.
- **TLS.** `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized: false` in an
  `https.Agent`/axios config.
- **Client-side "encryption".** Encrypting on the client with a key that lives in the
  bundle is obfuscation; report as a false control if anything relies on it.

## Data Exposure (`data-exposure-agent`)

- **Over-fetching into the client.** A GraphQL query or REST response handed whole to a
  component or Redux/Zustand store; sensitive fields exist in the browser even if not
  rendered. Check the API response shape, not the JSX.
- **Server/client boundary (Next.js/Remix).** A server component or `loader` returning
  more than the page needs; a `"use server"` function returning entity objects; data
  passed as props crossing into a client component becomes part of the HTML payload.
- **Browser storage and caching.** PII or tokens in `localStorage`, `IndexedDB`, service
  worker caches, or React Query/SWR persisted caches; sensitive responses with
  `Cache-Control: public`.
- **Logging and telemetry.** `console.log` of user objects left in production code;
  Application Insights / Sentry `setUser`, `trackEvent`, or breadcrumbs carrying PII,
  tokens, or full request bodies; URL query strings (which land in logs) carrying
  identifiers or tokens.
- **Error surfaces.** Stack traces or server error bodies rendered into the UI; Next.js
  `error.tsx`/`getServerSideProps` returning `err.message` from the server verbatim.
- **Node error handling.** Express default error handler in production; `res.json(err)`.

## Supply Chain (`supply-chain-agent`)

- `npm audit --omit=dev` / `pnpm audit` / `yarn npm audit` output named in your prompt;
  without it, reason from `package.json` versions and state the check was static.
- **Lockfile.** Missing, deleted in the diff, or not matching `package.json`
  (`npm ci` would fail). Mixed lockfiles (`package-lock.json` and `yarn.lock` both
  present). Pinned `resolutions`/`overrides` holding back a security patch.
- **Install scripts.** New dependencies with `preinstall`/`postinstall`; `.npmrc`
  disabling `ignore-scripts` project-wide; `npx <pkg>` in CI or `package.json` scripts
  without a version pin.
- **Registry config.** `.npmrc` with a non-default registry or an auth token committed;
  scoped internal packages without a registry mapping (dependency confusion).
- **Risky dependencies.** `eval`-based or network-calling build plugins; a package whose
  name is a near-miss of a popular one; very new or single-maintainer packages added for
  trivial functionality.
- **Build pipeline.** GitHub Actions on a mutable tag; `pull_request_target` running
  `npm install` on fork code; build secrets exposed as `NEXT_PUBLIC_*`/`VITE_*`.
- **CDN scripts.** `<script src>` from a third party without `integrity` (SRI) and
  `crossorigin`.

## Business Logic (`logic-abuse-agent`)

- **Client-only validation.** Zod/Yup/react-hook-form rules on the form with the
  server accepting the body unchecked; disabled buttons as the only guard against
  double-submit.
- **Client-computed values sent to the server.** Totals, prices, discounts, permission
  flags, or `isValid` booleans in the request body that the server trusts.
- **State machine on the client.** Wizard or workflow step enforced by React state or a
  route, while the final API call is directly reachable.
- **Optimistic UI.** Mutations applied locally before the server confirms, leaving the UI
  showing a state the server rejected — a finding only where the user can act on the
  false state.
- **Node concurrency.** Read-modify-write against a DB or cache without a transaction
  or atomic operation (`$inc`, `UPDATE ... SET x = x - 1 WHERE x > 0`); in-memory
  counters/limits that reset per instance and vanish under horizontal scaling.
- **Async error handling.** Unawaited promises or missing `catch` on a security-relevant
  path, so a failed check resolves as success; Express async handlers without an error
  wrapper.
- **Unbounded input.** Array or object bodies with no length cap feeding loops, DB
  queries, or `Promise.all`.

## Defensive Controls (`defensive-controls-agent`)

- **Cookies.** Session/auth cookies missing `HttpOnly`, `Secure`, `SameSite`
  (`express-session`, `cookie-session`, Next.js `cookies().set`).
- **CSRF.** Cookie-authenticated state-changing endpoints with `SameSite=None`/absent and
  no anti-forgery token; Next.js server actions reachable cross-origin.
- **CORS.** `cors({ origin: true })` or an origin reflected from the request combined with
  `credentials: true`; `Access-Control-Allow-Origin: *` on an authenticated API.
- **Security headers.** `helmet` absent or CSP disabled (`contentSecurityPolicy: false`);
  CSP with `'unsafe-inline'`/`'unsafe-eval'` in `script-src`; `X-Frame-Options`/
  `frame-ancestors` absent on pages that perform authenticated actions (clickjacking).
- **Rate limiting.** `express-rate-limit` or gateway policy absent on login, token,
  reset, and search endpoints; limits keyed on a spoofable `X-Forwarded-For` without
  `trust proxy` configured correctly.
- **Body and upload limits.** `express.json({ limit })` raised or absent; `multer` with
  no `fileSize`/`files` cap and client `mimetype` trusted for type checks.
- **Timeouts.** `fetch`/`axios` calls without `AbortSignal.timeout`/`timeout`; server
  `requestTimeout`/`headersTimeout` left unbounded.
- **postMessage.** `window.addEventListener('message')` handlers without an `origin`
  check; `postMessage(data, '*')` sending sensitive data.
- **Reverse tabnabbing.** `target="_blank"` without `rel="noopener"` on user-controlled
  links.

## Security Misconfiguration (`misconfig-agent`)

- **Environment gating.** `process.env.NODE_ENV !== 'production'` branches enabling
  mock auth, seed routes, verbose errors, or GraphQL playground/introspection — verify
  how `NODE_ENV` is set in the Dockerfile, hosting config, and CI; a build that omits it
  ships development behaviour.
- **Next.js config.** `next.config.js` with `productionBrowserSourceMaps: true`,
  `images.remotePatterns`/`domains` wildcarded (SSRF/proxy via the image optimiser),
  `rewrites`/`redirects` forwarding to a user-influenced destination, `experimental`
  flags that disable server-action origin checks, `poweredByHeader` left on.
- **Vite / webpack.** `server.host: true` or `--host` in a script that runs outside
  local dev; `build.sourcemap: true` for production; `define` injecting server env into
  the bundle; dev server `proxy` targets committed with internal hostnames.
- **Express / Node hosting.** `app.set('trust proxy', true)` (trusts any hop — rate
  limits and IP allow-lists become spoofable) or `trust proxy` absent behind a load
  balancer; `express.static` serving a directory containing `.env`, `.git`, or source;
  `x-powered-by` enabled; listening on `0.0.0.0` with no TLS terminator in front.
- **GraphQL.** Introspection and playground enabled in production; no depth/complexity
  limit; `debug: true` returning stack traces in `extensions`.
- **Exposed operational surfaces.** Storybook, `/docs`, Swagger UI, Bull/Agenda
  dashboards, `/metrics`, or detailed health endpoints deployed unauthenticated.
- **Containers & IaC.** Dockerfile running as root, `COPY . .` including `.env`,
  `FROM node:latest` unpinned, `npm install` (not `npm ci --omit=dev`) in the production
  stage; Bicep/Terraform/CDK with public storage buckets or static-site hosting serving
  more than `dist/`, open security groups, wildcard IAM; Vercel/Netlify/Azure Static Web
  Apps config exposing server env as public or lacking a `staticwebapp.config.json`
  route auth block for protected routes.
- **`tsconfig`/lint as a control.** `strict: false` or `noImplicitAny: false` is out of
  scope on its own; report only where a specific `any`-typed boundary admits the
  insecure value you traced.
