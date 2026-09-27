# Generated references

Inventories generated from the code, never written by hand (plan item D-3, Phase 7):

- the endpoint inventory - every `@WebServlet`, `web.xml` and `filters.xml` mapping and service route, tested
  against the OpenAPI documents and for collisions with PingFederate's own `web.xml`;
- the event and metric references;
- the OpenAPI 3.1 documents for the admin, federation, SSF, attestation, gm-api, device-enrolment and
  operations surfaces (D-4).

The directory is empty until then. A page that belongs here is one a build step writes and a build check
compares; the [contributing guide](../../CONTRIBUTING.md#generated-files) says how the generated files are
handled.
