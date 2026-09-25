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
  tracked or a line past its end, on this page or on `federation.html`.

Neither can tell whether a statement still says what the code does. When the code behind one moves, re-read
the statement, not just the line numbers.

`federation.html` is a page of its own: the OpenID Federation story in plain language, with the file behind each
part. The index links to it from the sidebar.
