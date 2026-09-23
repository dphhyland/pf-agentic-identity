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

The page is generated from the code, READMEs and Terraform, then audited claim by claim. It does not
follow later code changes. Rebuild it, or edit `index.html` and re-check the line references, when
the code moves.
