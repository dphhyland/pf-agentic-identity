# The configuration reference generated from the settings catalogues

## Changelog

- Plan item ST-4: `tools/config-reference.py` writes the configuration reference from the settings catalogues -
  one page per component in `docs/configuration/`, 24 of them, each saying which catalogue it came from, with the
  style guide's four columns and two more, Profile and Security - and the list of components in
  `docs/configuration/README.md`. The Build workflow's lint job runs it with `--check` and fails, naming the file,
  when a committed page is not what the catalogues generate. The settings A-Z index is written on demand
  (`--index FILE`) and never committed.
- `docs/extended-properties.json` is generated too, from every catalogue's extended-property entries: beside the
  federation module's ten names it now lists 24 more: the nine per-client `attestation_*` properties the token
  endpoint reads, the three `trust_chain_*` limits, and the attester's twelve `attestation_*` names,
  `attestation_asserted_context_resolver` among them. Its `_comment` and shape are unchanged apart from saying
  where it now comes from. The conformance rig's Terraform, which reads the file, declares every one of them,
  each described as read or written by the OIDF modules. Closes F-0041.
- The settings scan's exemption file sets `refuse-shipped-exemptions: yes`: only modules that are never shipped
  may be exempt, each with its reason, and the scan says every shipped module is held to its catalogues. With
  `--check`, the reference is held to the code both ways: the scan holds the code to the catalogues, and the
  generator holds the catalogues to the pages.
- `ConfigurationDocumentedTest` is gone; `FederationClientParamsTest` holds
  `FederationClientParams.EXTENDED_PARAM_NAMES` to pf-integration's `client-properties` catalogue.
- `docs/federation/configuration.md` keeps how a setting is read and what "wrong" means, points each part of the
  federation at the generated pages, and keeps what a row has no room for: examples of the JSON settings'
  shapes, and what the rows leave out.

## Before you deploy

1. **Declare the new extended properties.** A deployment that diffs its extended-properties Terraform against
   `docs/extended-properties.json` sees 24 names it has not seen: 21 `attestation_*` names and the three
   `trust_chain_*` limits. Declare every one of them, as `conformance/terraform/extended-properties.tf` does.
   PingFederate drops an extended property it has not been told about without a word, so a per-client attestation
   policy, chain limit or issuance setting written to a client is simply not applied (F-0041).

## Notes

Nothing a deployment sets changes: no reader was touched. The generated pages say what the catalogues say, and
the catalogues were written from the code by ST3A, ST3B and ST3C.

The generator is a standard-library Python tool beside the settings scan, not the plan's `tools/docs-generator`
Maven module last in the reactor: the catalogues are JSON in the source tree (plan decision 1), so it needs no
build, runs in the lint job in under a second, and reads the catalogues through the scan's own loader, so the
two cannot read them differently.

A list setting's Default cell says only "a list"; its description says how it is separated. Readers differ -
most split on commas only, a few on spaces or commas - and a space-separated `OIDF_FAPI2_CLIENTS` is one client
id, so no client is held to FAPI 2.0. Ten catalogue descriptions gained the separator their reader uses, and the
generator refuses a list whose description does not name one.

`docs/federation/configuration.md` lost its tables to the generated pages. Where a generated row says less than
the old one did, the page keeps the rest under the part of the federation it belongs to; where it says something
different, the catalogue follows the code.

F-0025 stays open for the rest of the settings work (plan items ST-5 to ST-7 and PR-2 to PR-5).
