# C# / .NET Security Reference

Stack notes for C#/.NET scopes. Sections are headed with the persona they belong to; each
agent reads only its own, alongside its language-agnostic brief.

---

## Authentication & Authorisation (`authz-agent`)

- **Attribute gaps.** A controller or action without `[Authorize]` where the default
  policy is not enforced globally. Verify whether a global filter or
  `RequireAuthorization()` is applied on the endpoint pipeline before reporting.
  `[AllowAnonymous]` beats everything — treat any newly added one as a finding to justify.
- **Minimal APIs.** `MapGet`/`MapPost` chains lacking `.RequireAuthorization()`.
- **Policy vs role.** `[Authorize(Roles = "...")]` with a magic string that does not
  match any registered role. Policies registered but never applied.
- **Resource-based authorisation.** ASP.NET's attribute model authorises the *endpoint*,
  never the *object*. Every `GetById`/`Update`/`Delete` must scope the query to the
  caller's tenant/project — look for `IAuthorizationService.AuthorizeAsync(user, resource, policy)`
  or an explicit ownership predicate in the query. Its absence is IDOR.
- **Claims.** Claims read without validating issuer; `ClaimsPrincipal` values trusted from
  a header (`X-User-Id`) rather than the validated token.
- **JWT config.** `TokenValidationParameters` with `ValidateIssuer`, `ValidateAudience`,
  `ValidateLifetime`, or `ValidateIssuerSigningKey` set to `false`;
  `RequireHttpsMetadata = false` outside local development.
- **Middleware order.** `UseAuthorization()` before `UseAuthentication()`, or either
  placed after `UseEndpoints`/the endpoint mapping — silently disables enforcement.
- **Background work.** Hosted services, message consumers, and hangfire/quartz jobs run
  with no user context; check that they are not reusing user-scoped authorisation
  assumptions.
- **Over-posting / mass assignment.** Model binding directly onto an EF entity, so a
  crafted body can set `IsAdmin`, `RoleId`, or `TenantId`. Require a dedicated
  request/command model, or `[Bind]`/`[FromBody]` onto a DTO.

## Injection (`injection-agent`)

- **EF Core.** `FromSqlRaw`, `ExecuteSqlRaw`, and `SqlQueryRaw` with an interpolated or
  concatenated string. The `FromSqlInterpolated`/`ExecuteSqlInterpolated` variants *are*
  parameterised — do not report those as injection unless the interpolated value is an
  identifier rather than a value.
- **Dapper / ADO.NET.** `new SqlCommand($"...{input}...")`, `CommandText +=`, or
  `DynamicParameters` built from raw input for identifiers.
- **Dynamic ordering.** `OrderBy(input)` via `System.Linq.Dynamic`, or an interpolated
  `ORDER BY`/column name. Parameterisation cannot protect identifiers — require an
  allow-list mapping from input token to a fixed column name.
- **NHibernate.** `CreateQuery`/`CreateSQLQuery` with concatenated HQL/SQL;
  `.hbm.xml` mappings containing a `formula` or `where` fragment built from input.
- **Deserialization.** `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`,
  `SoapFormatter`, `ObjectStateFormatter` on untrusted data — all are unsafe by design.
  `Newtonsoft.Json` with `TypeNameHandling` set to anything other than `None`.
  `JsonSerializerSettings` with a permissive `SerializationBinder`. `XmlSerializer` is
  generally safe; `DataContractSerializer` with unknown types is not.
- **XXE.** `XmlDocument`/`XmlTextReader` with `XmlResolver` set, or `XmlReaderSettings`
  with `DtdProcessing = Parse` on untrusted XML. Modern defaults are safe — report only
  where the default is explicitly overridden.
- **Command injection.** `Process.Start` with a composed `Arguments` string; prefer
  `ArgumentList`. `ProcessStartInfo` with `UseShellExecute = true` and user input.
- **Path traversal.** `Path.Combine(baseDir, userInput)` — note `Path.Combine` *discards*
  `baseDir` if `userInput` is rooted (`C:\`, `/`, `\\server\share`). Require
  `Path.GetFullPath` plus a `StartsWith(baseDir)` containment check. Same for
  `ZipArchive` entry extraction (zip-slip) and `ContentDisposition` filenames.
- **XSS in Razor/Blazor.** `@Html.Raw(...)`, `MarkupString`, `HtmlString`,
  `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` used for HTML context, or user data
  emitted inside a `<script>` block. `@` output is HTML-encoded by default — do not
  report the safe default.
- **SSRF.** `HttpClient` called with a user-supplied URL. Check for an allow-list and
  whether `HttpClientHandler.AllowAutoRedirect` lets an allow-listed host redirect to
  an internal address.
- **Open redirect.** `Redirect(returnUrl)` without `Url.IsLocalUrl(returnUrl)`.

## Secrets & Cryptography (`secrets-crypto-agent`)

- Connection strings with credentials, API keys, or certificates in `appsettings.json`,
  `appsettings.Development.json`, `launchSettings.json`, `web.config`, `*.pubxml`,
  Dockerfiles, Bicep/Terraform, or GitHub workflow files. Expect a secret manager
  (Key Vault, AWS Secrets Manager, Vault), workload/managed identity, or user-secrets
  instead.
- `RandomNumberGenerator` is correct for tokens; `System.Random` and `Guid.NewGuid()` are
  **not** acceptable sources of security tokens, reset codes, or session ids.
- `MD5`, `SHA1`, `TripleDES`, `RC2`, `DES`, `RijndaelManaged` with `CipherMode.ECB`, or a
  hardcoded/zero `IV`. Prefer `AesGcm`/`AesCcm` or `Aes` in CBC with a random IV and a
  separate MAC.
- Password hashing: `PasswordHasher<T>` or `Rfc2898DeriveBytes` with a high iteration
  count and an explicit SHA-256+ HMAC. A bare `SHA256(password)` is a HIGH finding.
- `CryptographicOperations.FixedTimeEquals` for comparing secrets/MACs; a plain `==`,
  `SequenceEqual`, or `string.Equals` on a token is a timing oracle.
- TLS: `ServerCertificateCustomValidationCallback = (…) => true`,
  `DangerousAcceptAnyServerCertificateValidator`, or
  `ServicePointManager.ServerCertificateValidationCallback` returning `true`.
- ASP.NET Data Protection: keys persisted to a location that is not encrypted or is
  shared inappropriately; `SetApplicationName` mismatches that silently break token
  validation across instances.

## Data Exposure (`data-exposure-agent`)

- Controller actions returning EF/NHibernate entities directly instead of an API model.
  Navigation properties can drag in whole related graphs, including other users' rows.
- `[JsonIgnore]`/`[IgnoreDataMember]` removed from a sensitive property in the diff.
- `UseDeveloperExceptionPage()` or `IncludeErrorDetailInResponse`/detailed errors reachable
  outside development; `ProblemDetails` populated with `ex.ToString()`.
- Logging: `_logger.LogInformation("... {@Request}", request)` structured-logging an object
  containing credentials or PII; logging full `HttpRequest`/`HttpResponse` bodies;
  exception logging that includes a connection string.
- `IQueryable` returned from a repository or exposed via OData without a `$top` cap —
  unbounded export.
- EF global query filters (`HasQueryFilter`) for tenancy being bypassed by
  `IgnoreQueryFilters()`, raw SQL, or a second `DbContext`.

## Supply Chain (`supply-chain-agent`)

- `dotnet list package --vulnerable --include-transitive` output named in your prompt;
  without it, reason from `.csproj`/`Directory.Packages.props` versions and state that the
  check was static.
- `packages.lock.json` missing, stale, or deleted in the diff when
  `RestorePackagesWithLockFile` is enabled.
- Floating versions (`Version="8.*"`) or `PackageReference` without a version where
  central package management is not in use.
- A `NuGet.config` adding a non-official source, or removing `<clear/>` before adding
  sources (enables dependency confusion against internal package names).
- GitHub Actions pinned to a tag rather than a commit SHA; `pull_request_target` workflows
  checking out `github.event.pull_request.head.sha` and running project code with secrets;
  `permissions:` not narrowed.

## Business Logic (`logic-abuse-agent`)

- Read-modify-write without a transaction or a concurrency token. EF: check for
  `[Timestamp]`/`IsConcurrencyToken`, an explicit transaction, or a database-side atomic
  update. A `FirstOrDefault` → mutate → `SaveChangesAsync` sequence on a balance, quota,
  status, or counter is the classic double-spend shape.
- `SaveChangesAsync` called multiple times in one handler with no transaction — partial
  commit on failure.
- FluentValidation validators registered but not executed on a given path (e.g. a handler
  invoked directly from a background job or a second controller).
- `CancellationToken` not propagated — long operations that cannot be aborted (DoS
  amplification) — and, conversely, a cancellation that leaves state half-written.
- Client-supplied money/quantity/price/id fields on a command, or over-posted onto an
  entity, that are used without a server-side re-read or re-computation.

## Defensive Controls (`defensive-controls-agent`)

- Cookies: `HttpOnly`, `Secure`, `SameSite` on auth cookies; `CookiePolicyOptions`.
- `UseHsts()`, `UseHttpsRedirection()` present for internet-facing apps.
- CORS: `AllowAnyOrigin()` combined with `AllowCredentials()` (ASP.NET throws on this
  combination — the dangerous variant is `SetIsOriginAllowed(_ => true)` with credentials).
- `[ValidateAntiForgeryToken]` / `AutoValidateAntiforgeryToken` on cookie-authenticated
  state-changing endpoints.
- `catch (Exception) { }` or a catch that returns a success/permissive result on a
  security path — fail-closed is required for authorisation and validation.
- `HttpClient` without a `Timeout`; `MaxRequestBodySize` raised without justification.
- No audit record written for privilege changes, admin actions, or data export.
- Rate limiting (`AddRateLimiter` / gateway policy) absent on login, token, reset, and
  invite endpoints.

## Security Misconfiguration (`misconfig-agent`)

- **Environment gating.** `app.Environment.IsDevelopment()` branches that enable
  `UseDeveloperExceptionPage`, Swagger, detailed errors, or a fake auth handler —
  check how `ASPNETCORE_ENVIRONMENT` is actually set in the deployment (Dockerfile,
  Bicep/Terraform app settings, pipeline). A missing or misspelled value defaults to
  `Production`; an explicit `Development` in a deployed profile is a finding.
- **Swagger / OpenAPI.** `UseSwagger()`/`UseSwaggerUI()` outside the development branch
  or without `RequireAuthorization()`; `MapHealthChecks` returning detailed component
  status publicly; `MapPrometheusScrapingEndpoint`/`/metrics` unauthenticated.
- **Settings precedence.** `appsettings.Production.json` or environment variables that
  override a secure default from `appsettings.json` (e.g. `"DetailedErrors": true`,
  `"Logging:LogLevel:Default": "Trace"`, `RequireHttpsMetadata: false`).
- **Kestrel / hosting.** `KestrelServerLimits` (`MaxRequestBodySize`,
  `MaxRequestHeadersTotalSize`) set to `null`/unlimited; `UseForwardedHeaders` with
  `KnownProxies`/`KnownNetworks` cleared so any client can spoof `X-Forwarded-For`/`-Proto`;
  listening on `http://0.0.0.0` behind no TLS terminator.
- **`web.config` (Framework / IIS).** `<customErrors mode="Off">`, `<compilation debug="true">`,
  `<trace enabled="true">`, `<directoryBrowse enabled="true">`, `requestValidationMode`
  lowered, `maxRequestLength`/`maxAllowedContentLength` raised, `<httpRuntime enableVersionHeader>`
  left on.
- **Identity / OIDC registration.** Redirect URIs with wildcards or `http://`; implicit
  flow enabled; app registration secrets with no expiry; `AllowedCorsOrigins`/`RedirectUris`
  loaded from a setting that production can widen.
- **Containers & IaC.** Dockerfile running as root (no `USER app`), secrets in `ENV`/`ARG`,
  `FROM mcr.microsoft.com/dotnet/aspnet:latest` unpinned; Bicep/Terraform with
  `publicNetworkAccess: 'Enabled'`, `allowBlobPublicAccess: true`, SQL firewall
  `0.0.0.0–255.255.255.255`, `minimumTlsVersion` below 1.2, Key Vault without purge
  protection or with `enableRbacAuthorization` off and wide access policies, App Service
  `httpsOnly: false` or `ftpsState: 'AllAllowed'`.
