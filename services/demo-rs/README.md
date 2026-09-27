# demo-rs (relocated)

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo.**

`demo-rs` moved to [`libs/rs-validation`](../../libs/rs-validation) in 0.5.0 (plan item X-D01). The package,
`com.pingidentity.ps.oidf.rs`, is unchanged, so imports keep compiling; the constructors are not, because a replay
store is now required - see the [rs-validation README](../../libs/rs-validation/README.md).

What is left here is a relocation POM. A build that depends on `com.pingidentity.ps.oidf:demo-rs` at 0.5.0 or later
resolves `com.pingidentity.ps.oidf:rs-validation` at the same version, and Maven warns with the new coordinates.
Change the dependency to `rs-validation` to silence the warning. Releases before 0.5.0 are the `demo-rs` jar they
always were.
