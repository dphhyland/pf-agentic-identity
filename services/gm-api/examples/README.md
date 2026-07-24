# Examples

`java/GrantManagementClient.java` — a single-file, JDK-only client for the API.

```bash
java java/GrantManagementClient.java --pf https://localhost:9131 \
  --client acme-budgeting --secret "$SECRET" --grant "$AGID" --account 222
```

The curl walkthrough and the Go client library live with the AS-agnostic reference,
[grant-evaluation-api](https://github.com/dphhyland/grant-evaluation-api)/`examples`.
