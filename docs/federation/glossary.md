# Glossary

The words these pages use, in plain terms. Where a word is OpenID Federation 1.0's, its section is given.

**Anchor** - see *trust anchor*.

**AuthZEN** - the OpenID Foundation's Authorization API 1.0: a standard way to ask a policy decision point
"may this subject do this action on this resource?" and get yes or no back. PingAuthorize speaks it.

**Automatic registration** (§12.1) - a client becoming a PingFederate client on its first request, with no
registration step, because its trust chain says who it is.

**Chain** - see *trust chain*.

**Client assertion** - a short-lived JWT a client signs to prove it holds its keys (`private_key_jwt`). Agents
send one at the token endpoint; at the federation endpoints a client sends one to authenticate.

**Constraints** (§6.2) - limits a superior puts on everything below it: how deep the tree goes, which host
names may be used, which roles entities may play.

**Delegation** (§7.2) - a signed permission from a Trust Mark type's owner that lets another issuer issue
marks of that type.

**Discovery** - building a trust chain by fetching statements, starting from the entity's own Entity
Configuration and following its `authority_hints` upwards.

**Domain authority** - an organisation that vouches for its own agents. PingFederate can be one, hosting the
agents' Entity Configurations for them.

**Entity** - anything in a federation: an OP, a relying party, an agent, an intermediate, a trust anchor.

**Entity Configuration** (§3) - an entity's signed statement about itself, served at
`https://<entity>/.well-known/openid-federation`.

**Entity Identifier** - an entity's name: an https URL, like `https://agents.example.com/a1`. It is also its
`client_id` when it registers.

**Explicit registration** (§12.2) - a client registering before it makes any request, by sending its Entity
Configuration or its whole trust chain to `/federation/register`.

**Extended properties** - PingFederate's extra fields on a client. The federation support marks each client it
registers with several of them - its status, its expiry, its anchor - and PingFederate keeps only the ones it
has been told about ([docs/extended-properties.json](../extended-properties.json)).

**Federation Entity Keys** (§1.2) - the keys an entity signs federation statements with, published in the
`jwks` of its Entity Configuration. Distinct from the keys it uses as an OP or a relying party.

**Fetch endpoint** (§8.1) - where a superior serves the statement it makes about one of its subordinates.

**Historical keys** (§8.7) - the keys an entity signed with before its current ones, published so that old
statements can still be checked.

**Hosted agent** - an agent whose Entity Configuration PingFederate serves and signs for it, so the agent needs
no web server of its own.

**Intermediate** - an entity between a leaf and a trust anchor that vouches for the entities below it.

**Leaf** - an entity at the bottom of the tree: an OP, a relying party, an agent.

**Metadata** (§5) - what an entity says about itself, one block per role (`openid_provider`,
`openid_relying_party`, `oauth_client`, `federation_entity`).

**Metadata policy** (§6.1) - rules a superior sets on its subordinates' metadata: this value, only these
values, at least these values.

**Obligation** - what a policy decision point adds to a yes: fewer scopes, a shorter registration, a Trust Mark
to hold. Here obligations only ever narrow.

**OGNL criterion** - an expression PingFederate evaluates before it issues a token. The federation support
provides two (`validateTrustChain`, `federationPolicy`) for deployments that gate token issuance that way.

**OP** - OpenID Provider: the server that authenticates users and issues tokens. PingFederate.

**PAR** - Pushed Authorization Requests: a client POSTs its authorization request first and gets back a
reference to use at the authorization endpoint.

**PDP** - policy decision point: the service asked for a yes or no, such as PingAuthorize.

**Registration lifetime** (§12.3) - how long a federation registration lasts: never longer than the chain it
came from.

**Relying party (RP)** - a client application that signs users in with an OP.

**Request object** - an authorization request as a signed JWT. A relying party registering at the
authorization endpoint proves it holds its keys by signing one.

**Resolve endpoint** (§8.3) - where an entity asks another to build and check a chain for it and hand back the
result, signed.

**Subordinate Statement** (§3) - the signed statement a superior makes about an entity below it: its keys, and
any metadata, policy and constraints for it.

**Superior** - the entity directly above another in the tree, the one that issues its Subordinate Statement.

**Sweeper** - the background task that disables expired federation clients in PingFederate.

**Trust anchor** (§1.2) - an entity everyone in a federation trusts, whose keys are pinned by hand. Every chain
ends at one.

**Trust chain** (§4) - the statements from an entity up to a trust anchor, each signed by the one above.

**Trust Mark** (§7) - a signed badge an issuer gives an entity to say it passed something. A federation can
require them.

**Trust Mark issuer** - an entity the trust anchor allows to issue marks of a type (`trust_mark_issuers`).
