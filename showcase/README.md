# Agentic Identity showcase

The ID Partners showcase explains this repository’s PingFederate extensions for management and technical readers. It covers capabilities, installation requirements and test evidence. Source links identify the supporting files and lines.

## Pages

- `index.html` presents the components, access checks and local simulations. It also includes configuration guidance and the documentation viewer.
- `federation.html` explains federation registration, policy controls and lifecycle limits.
- `conformance.html` reports six OpenID Foundation test plans and their limitations. Locally hosted results do not constitute certification.
- `screens/` contains eight PingFederate console screenshots.

The main page includes its styles, scripts and data. The documentation viewer loads generated content from `docs.js`, which is not tracked in Git. Without that file, the other views work and the viewer displays build instructions. The site requires no network access to read locally.

Components are labelled implemented, opt-in, proposed or unverified. The simulations make no server calls. They model the documented checks, including their limits.

## Local preview

1. From the repository root, install the pinned document renderer and build the documentation:

   ```sh
   npm ci --prefix tools
   node tools/build-showcase-docs.mjs
   ```

2. Start a local server:

   ```sh
   python3 -m http.server 8765 --bind 127.0.0.1
   ```

3. Open [the showcase](http://127.0.0.1:8765/showcase/). Direct links include `#flow`, `#setup`, `#rar`, `#rar#rar-config` and `#doc:docs/unverified.md`.

## Screenshots

Screenshots show the local agentic-demo instance on PingFederate 13.0.3 with the RAR plugin and `oidf.war` installed. Secrets are redacted.

Captions identify differences from repository defaults. The demo uses an OGNL issuance criterion without the token-endpoint filter. Its RAR processor permits requests on engine errors and skips TLS verification.

## Maintenance

Rebuild `docs.js` after changing a document. The renderer includes tracked Markdown and the coverage dashboard when a generated copy exists at `docs/coverage-dashboard.md`.

Check source and documentation links after editing showcase copy:

```sh
node tools/build-showcase-docs.mjs
python3 tools/check-showcase-links.py
```

The link checker validates tracked source files, line references and documentation targets across all three pages. A missing generated dashboard produces a note. The checks do not verify whether copy accurately describes the implementation; review the cited source when behaviour changes.

CI generates the coverage dashboard and documentation, checks links and uploads `showcase/` as a build artefact after the required build steps pass.

## Hosting

Local pages use relative links into the repository. For standalone hosting, `tools/build-microsite.py` copies the pages and images and converts source links to GitHub links at a fixed commit.

```sh
python3 tools/build-microsite.py --ref main
railway up build/microsite --path-as-root --service site
```

`showcase/deploy/` contains the nginx configuration. The site address is [agentic-identity.idpartners.global](https://agentic-identity.idpartners.global), in Railway project `agentic-identity-site`. Its DNS CNAME points to the service’s `*.up.railway.app` target.

Rebuild and redeploy after editing a page. `showcase/` is the source; `build/microsite/` is generated output.
