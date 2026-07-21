Workgroup:     OpenID AuthZEN
Published:
Authors:        D.Hyland, Ed
                ID Partners
                
# AuthZEN Profile for OAuth 2.0 and Open ID. 
## Abstract
This specification defines a profile for using AuthZEN (Authorization Evaluation) which would be used by an OAuth 2.0 client on the Autorization Server or Resource Servers it has been granted access to. It provides a standardized approach for performing access evaluations by extending the AuthZEN information model to work seamlessly with OIDC and OAuth 2.0 protocols. The profile specifies how to handle evaluation requests and responses while maintaining compliance with existing OIDC and OAuth standards, including support for scopes, claims, and Rich Authorization Requests.


## 1. Introduction

In today’s dynamic security landscape, merely relying on static scopes or basic claim checks is insufficient to accurately determine whether a user or client should be granted access. Modern authorization evaluations often require complex decision-making that goes beyond simple scope- or claim-based controls, considering contextual factors such as user risk level, resource sensitivity, real-time threat indicators, and environmental variables (e.g., device type or geolocation).

By externalizing complex authorization rules into a centralized policy decision point (PDP), organizations can maintain a single source of truth for security policies. This not only streamlines the development process—ensuring more consistent policy enforcement across multiple applications and channels—but also strengthens the overall security posture by reducing the likelihood of overlooked or inconsistent access checks.

Fine-grained access control further empowers organizations by defining who can access specific resources under particular circumstances, thereby creating policies that are more nuanced than a simple “allow” or “deny.” This granular approach ensures that users only see or modify data and functions they are legitimately entitled to, reducing the potential attack surface and minimizing the risk of inadvertent data exposure.

AuthZEN 1.0 formalizes how a Policy Enforcement Point (PEP) communicates with a Policy Decision Point (PDP) by defining the core elements of each evaluation request and response: who the user is (Subject), what they intend to do (Action), which resource is being accessed (Resource), any additional environmental or contextual properties (Context), and the resulting Decision. By codifying these elements, AuthZEN 1.0 provides a uniform framework for consistent, repeatable, and transparent policy enforcement.

However, AuthZEN 1.0 is framed strictly in a PEP-to-PDP context and does not specify how its concepts align with OAuth 2.0 or OpenID Connect (OIDC). As a result, implementers looking to integrate AuthZEN with token-based flows or identity federation mechanisms must extend or adapt the standard to ensure compatibility with the broader identity ecosystem.

The AuthZEN Profile for OAuth and OpenID addresses this gap by defining a standardized approach for performing authorization evaluations within the collection of OpenID and OAuth 2.0 specifications. It extends the base AuthZEN information model defined in Section 5 of AuthZEN 1.0—expanding the handling of client assertions, subject, location, scopes, claims, authorization_details, and including guidance on returning decision context to the client.


### 1.1 Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 [RFC2119].

In the .txt version of this specification, values are quoted to indicate that they are to be taken literally. When using these values in protocol messages, the quotes MUST NOT be used as part of the value. In the HTML version of this specification, values to be taken literally are indicated by the use of this fixed-width font.

## 2. AuthZEN Information Model

This section is based upon the information model defined in [Section 5](https://openid.net/specs/authorization-api-1_0-01.html#name-information-model) of the AuthZEN 1.0 implementers draft. 

# 3. Evaluation Request

Supports all Authorization Evaluation semantics with exceptions defined below. 


Client Assertions, self issued or issued by a trusted authority, play a critical part  in the authorization decision by a Policy domain. 


## 3.1 Subject

When processing authorization evaluation requests the subject handling follows specific rules that differ from the base AuthZEN specification:

### 3.1.1 Subject Resolution

The subject entity as defined in the base AuthZEN specification MUST be ignored. Instead, the subject for evaluation MUST be determined from one of the following sources:

1. The OIDC subject identifier (`sub`) from the access token or ID token associated with the request
2. The actor identifier in cases involving token exchange or delegation

### 3.1.2 Subject Identifiers

Subject identifiers provided in the response or as a resource identifiers in the request MUST conform to Section 8 of the OpenID Connect Core specification, with the following requirements:

1. Implementations MUST support pairwise subject identifiers consistent with OIDC Core Section 8.1.
2. The subject identifier MUST be unique for each Relying Party
3. The format MUST follow the requirements specified in OIDC Core Section 8.1
4. In cases involving token exchange, the subject and actor relationships MUST be preserved according to RFC 8693

### 3.1.3 Processing Rules

When processing authorization evaluations:

1. The authorization server MUST validate that the subject identifier is valid and active
2. The evaluation MUST consider the subject type (pairwise or public) when applying authorization policies
3. If a subject cannot be determined from the request context, the evaluation MUST fail with an appropriate error response
4. Actor claims, when present, MUST be validated according to RFC 8693 token exchange requirements

### 3.1.4 Error Handling

The following error conditions MUST be handled:

1. Invalid or expired subject identifiers
2. Missing required subject context
3. Malformed actor claims
4. Subject identifier format violations


## 3.2 Location 

- Must be considered with every evalutation. If not provided will be treated as a query, and return all locations where are resource may be accessed. 
- A Location or Resource value MUST be provided.?


## 3.3 Client Scopes and Claims

The client grant may hold scopes, claims or authorization details. The evaluation must apply these constraints to the evaluation response. 

The evalaution will not return scopes, claims, authorization_details in the evaluation response. This may be access by the Grant Management API. 

## 3.4 Rich Authorization Requests



# 4. Access Evaluation

Supports all Authorization Evaluation semantics in [Section 6.](https://openid.net/specs/authorization-api-1_0-01.html ) with exceptions defined below. 

### 4.1 Access Evaluation Request

`subject`: OPTIONAL. If ommited the subject of the access token will be used. 

If a subject identifier is provided that is not the subject of the grant, then the evalaution will consider it as acting on behalf of the user.

If there is no identity assocaited with the client grant, a `400 Bad Request` will be returned. 

`location`: OPTIONAL. The location of the resource for the evalution. The same resource may be made available through a number of locations. 
If the location value is not provided, the evaluation will assume all.

### 4.2 Reason Object

Must conform with RFC7807 Section 3


The `reason` object will provide only the `reason_user` data,reason `id` and `reason-admin` data MUST NOT be provided to the client.

```
{
   "reasons": [
       {"reason-code-1": "Requires US Tax Residency"}
   ]
}
```

### Sending back identity information in the Reason. 

### 4.2 Errors

Evaluation Errors: When the evaluation is not well formed etc. 
PDP errors: where the policy evalution fails (4xx, 500 etc)


## 5. Protected Resource Metadata

Extension to support a new parameter: authorization_enquiry_supported. 
This will signal to the client that it supports the providing of an Authorisation Evaluation in an HTTP Header.
`authorization-evaluation`. 



## 6. IANA Considerations

This specification does not introduce any new identifiers that would require registration with IANA.

## 7. Security Considerations



## 8. Normative References

[RFC4001] Daniele, M., Haberman, B., Routhier, S., and J. Schoenwaelder,
“Textual Conventions for Internet Network Addresses”,
RFC 4001, DOI 10.17487/RFC4001,
February 2005,
<https://www.rfc-editor.org/rfc/rfc4001>.

[RFC6749]  Hardt, D., Ed.,
“The OAuth 2.0 Authorization Framework”,
RFC 6749, DOI 10.17487/RFC6749,
October 2012,
<https://www.rfc-editor.org/rfc/rfc6749>.

[RFC8259] Bray, T., Ed.,
“The JavaScript Object Notation (JSON) Data Interchange Format”,
STD 90, RFC 8259, DOI 10.17487/RFC8259,
December 2017,
<https://www.rfc-editor.org/rfc/rfc8259>.

[RFC9110] Fielding, R., Ed., Nottingham, M., Ed., and J. Reschke, Ed.,
“HTTP Semantics”, STD 97, RFC 9110,
DOI 10.17487/RFC9110,
June 2022,
<https://www.rfc-editor.org/rfc/rfc9110>.

[RFC9493] Backman, A., Ed., Scurtescu, M., and P. Jain,
“Subject Identifiers for Security Event Tokens”,
RFC 9493, DOI 10.17487/RFC9493,
December 2023,
<https://www.rfc-editor.org/rfc/rfc9493>.

[XACML] Godik, S., Ed., and T. M. (Ed.), Ed.,
“eXtensible Access Control Markup Language (XACML) Version 1.1”,
OASIS, 2006,
<https://www.oasis-open.org/committees/xacml/repository/cs-xacml-specification-1.1.pdf>.

## Appendix A. Terminology

## Appendix B. Acknowledgements

## Appendix C. Document History 

## Appendix D. Notices