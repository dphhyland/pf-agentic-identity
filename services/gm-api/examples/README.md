# Examples

`java/GrantManagementClient.java` — a single-file, JDK-only client for the API.

```bash
java java/GrantManagementClient.java --pf https://localhost:9131 \
  --client acme-budgeting --secret "$SECRET" --grant "$AGID" --account 222 \
  --cacert pf-ca.pem
```

`--cacert FILE` trusts the PEM certificates in `FILE` - a demo PingFederate's self-signed certificate, or the CA
a private deployment's certificate chains to - and checks the chain and the host name as for any other server.
Leave it out for a certificate from a CA the JDK already trusts. There is no option that turns verification off:
the `--insecure` earlier versions offered is gone (0.6.0, F-0163), since this is code people copy and its next
request carries a client secret.

The curl walkthrough and the Go client library live with the AS-agnostic reference,
[grant-evaluation-api](https://github.com/dphhyland/grant-evaluation-api)/`examples`.
