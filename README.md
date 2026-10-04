# Expensify MCP HTTP

Streamable HTTP MCP for Expensify reports, expenses and policies. The existing thirteen tool contracts remain available at `/mcp`.

## Authentication

Every MCP **POST, GET and DELETE** must carry the same caller credentials, including notifications and resumed sessions. Session IDs identify protocol state; they do not authenticate a caller.

Direct mode accepts `Authorization: Bearer partnerUserID:partnerUserSecret`. The first colon separates ID from secret, so secrets can contain colons. JSON credentials using string fields `partnerUserID`/`partnerUserSecret` or `id`/`secret` are also supported. Fields must be nonempty. A structurally valid pair is checked by Expensify when a tool calls the provider. It is not a Finney user token. Direct mode works without broker configuration and takes precedence when an Authorization header is supplied. Invalid explicit Authorization never falls back to the broker.

Broker mode requires the existing install identity (`BROKER_INSTALL_BEARER`, `BROKER_JWT_KEY`, `BROKER_CLIENT_NAMESPACE`) **and** `BROKER_PRINCIPAL_HMAC_KEY`. Each request supplies:

- `X-Broker-Principal`: the gateway's stable caller principal.
- `X-Broker-Principal-Sig`: HMAC-SHA256 of that principal, encoded as unpadded base64url, using the gateway/service shared HMAC key.

`BROKER_PRINCIPAL_HEADER` can override the principal header name. Missing or invalid proofs receive 401; an unconfigured broker mode receives 503. Anonymous fallback and unsigned principal mode are disabled, including when `BROKER_FALLBACK_PRINCIPAL` remains in an old deployment. An authenticated caller without an Expensify connection receives the existing `connection_required` tool result.

These are the service's existing direct-provider and signed-gateway contracts; this repair does not introduce OAuth or claim OAuth MCP authorization conformance. Static HMAC proofs are bearer-equivalent and replayable if leaked. Use TLS and keep all credentials and signatures private.

## Sessions and errors

Initialization returns the required `Mcp-Session-Id` header. Include it together with authentication on later requests. A different mode, principal or partner credential pair cannot access or delete that session (403). Equivalent JSON/colon representations of the same pair are accepted. Unknown or expired session IDs return 404; initialize again without the old ID. Restart clears all session state.

Malformed partner credentials receive 400; missing/unsupported Authorization syntax receives 401. Errors use fixed messages and do not return upstream bodies or submitted secret fragments. Routine logs and health/error bodies omit session IDs. Credentials are held only in process memory for their session and are not written to disk.

`GET /health` is public. `brokerConfigured` means the three install identity fields are present; `brokerReady` also requires the HMAC key. `rawBearerAvailable` remains true. Health does not prove the provider account is usable.

## Build and verification

Use Node20 or newer. `npm ci`, `npm run build` and `npm start` retain the production entrypoint. `npm test` builds and runs the isolated Node test suite, including real HTTP/SDK transport, mocked outbound broker/provider requests, concurrent identity checks and compiled-process startup. No test uses live provider credentials. There is no separate lint command; TypeScript build and diff checks are the static gates.

The existing Docker multi-stage build compiles every `src` module and runs `dist/index.js`; no deployment layout change is required.

## Restoration and monitoring

Deploy only an independently reviewed immutable commit to the existing Expensify service/environment. Preserve its domain, tenant account, direct credentials and assignments. Unsigned broker clients must configure matching HMAC keys before use; do not re-enable fallback. A fresh process invalidates old sessions.

The deployment operator verifies successful startup and health, negative unauthenticated MCP probes, then authenticated initialize and tools/list. Perform exactly one approved `policies_list {}` through the original cloud agent/account. This check is read-only; do not export reports or exercise write tools to qualify the repair.

For the first ten minutes and the authorized read, check deployment restart/crash counters, HTTP 401/403/503 rates and generic request failures. Healthy signals are stable process, accurate readiness, rejected anonymous requests and successful assigned read. Repeated authenticated failures or restarts stop qualification and trigger diagnosis. Never print credentials/signatures/session IDs or roll back to the unauthenticated candidate as a usable service. Broker configuration may remain unavailable while the original direct account works.
