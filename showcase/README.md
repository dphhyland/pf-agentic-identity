# Agentic Identity showcase

A single-page HTML site, branded for ID Partners, that presents this repository as a product: the
servlets, SDK plugins, libraries and services, the gates a token request passes, packaging, a
PingFederate set-up guide, standards and assurance, and every tracked document rendered as a page.

`index.html` carries its CSS, JavaScript, data, documents and logos inline. The only external files
are the PingFederate console screens in `screens/`. No build step or network access is needed to
view it.

For a local preview with working links into the repository, run this from the repository root:

```sh
python3 -m http.server 8765 --bind 127.0.0.1
```

Then open http://127.0.0.1:8765/showcase/. Hash navigation supports direct links to each view, for
example `#flow`, `#setup`, `#rar`, `#rar#rar-config` or `#doc:docs/unverified.md`.

## What is on it

- **Components.** Each module page lists what it does, its failure behaviour, endpoints, packaging
  and recorded limits. A Configuration section lists every setting the module reads (environment
  variables, system properties, servlet init-params, client extended properties and admin-console
  fields), with its default and effect.
- **PingFederate set-up.** Procedures for the admin console and the runtime host, with console
  paths, steps and field values. Eight screens illustrate the RAR processor, authorisation detail
  types, extended properties, token managers, access token mappings, the attestation issuance
  criterion and OAuth clients.
- **Documentation.** All tracked Markdown in the repository, rendered as HTML with an outline and
  working cross-links.
- **Playground.** A local simulation of two real gate sequences. It calls nothing, and it does not
  model amounts because no code in this repository compares them.

Every statement carries a small boxed link to the file behind it, labelled with the line numbers.
Components are marked implemented, opt-in, proposed or unverified.

## About the console screens

The screens were captured from the local agentic-demo PingFederate 13.0.3 instance, which has the
RAR plugin and `oidf.war` installed. Secret values are redacted. That instance differs from this
repository's defaults in ways the captions call out: it gates tokens with the OGNL issuance
criterion alone (no token-endpoint filter), and its RAR processor runs with `Fail open on engine
error` on and TLS verification skipped.

## Keeping it current

The page was generated from the code, READMEs and Terraform, then audited claim by claim. Two parts of that
are now mechanical, and CI checks both:

- **The documents.** `node tools/build-showcase-docs.mjs` renders every tracked Markdown file into the page's
  `DOCS_HTML` (run `npm ci --prefix tools` once first; the renderer is pinned). Run it after changing any
  document - the coverage dashboard included - or `--check` fails the build.
- **The source links.** `python3 tools/check-showcase-links.py` fails when a boxed link names a file that isn't
  tracked or a line past its end, on this page, on `federation.html` or on `conformance.html`.

Neither can tell whether a statement still says what the code does. When the code behind one moves, re-read
the statement, not just the line numbers.

## The other two pages

`federation.html` is the OpenID Federation story in plain language, with the file behind each part.
`conformance.html` is what the OpenID Foundation's suite says about a PingFederate built from `conformance/`:
the six plans and their results, the two FAPI 2.0 rules a filter in this repository enforces because the
product cannot be configured to, the CIBA gap no configuration closes, and what has not been tested at all.
Its results table is `conformance/README.md`'s, and it repeats that README's own point that a run against a
suite you host is not a certification. The index links to both from the sidebar.

## Hosting it

Served from the repository root the pages reach the code with relative links. Hosted on their own there is no
repository beside them, so `tools/build-microsite.py` rewrites every such link to the file on GitHub at one
commit, keeping the lines, and copies in the images:

```sh
python3 tools/build-microsite.py --ref main     # -> build/microsite/ (git-ignored)
railway up build/microsite --path-as-root --service site
```

`showcase/deploy/` holds the nginx image that serves the result. The site runs at
https://agentic-identity.idpartners.global (Railway project `agentic-identity-site`), which needs a CNAME from
that host to the service's `*.up.railway.app` target. Rebuild and redeploy after changing any page: the pages
are the source, `build/microsite/` is only an artefact.
