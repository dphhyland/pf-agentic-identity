# Proposed Changes to Grant Management API

## Abstract 
This specification extends the Grant Management API to enable real-time evaluation of access rights against existing grants . By introducing a standardized Grant Evaluation API endpoint, the extension allows clients to verify ongoing access permissions while considering contextual attributes and current grant constraints. The proposal defines the necessary protocol flows, API formats, and security requirements, making it particularly valuable for scenarios like Open Banking and healthcare where continuous verification of complex permissions is essential.

## [Add to Section 3: Use cases supported]

### 3.8 Evaluating Access Against a Grant

A client needs to evaluate whether a subject has access to a resource under an existing grant. This evaluation must consider:
- The subject's identity
- The grant's current permissions
- The specific resource/location being accessed
- Any contextual attributes

Examples:

In banking, a TPP may need to verify if a customer still has access to specific accounts under an existing consent.

In healthcare, an application may need to check if a practitioner has access to patient records under their existing authorization.

## [Add to Section 5: OAuth Protocol Extensions]

### 5.7. Grant Evaluation

Grant evaluation allows clients to determine if access is permitted under a specific grant without requiring a new authorization flow. The evaluation considers:

1. The current state and permissions of the grant
2. The subject identity from the bearer token
3. The requested action and resource/location
4. Any provided context

## [Add new Section 6.7 to the Grant Management API]

### 6.7. Grant Evaluation API

Clients can evaluate access under a specific grant using this API endpoint.

### 6.7.1. API Authorization 

Using the Grant Evaluation API requires the client to obtain an access token authorized for this API. The token must include the scope:

grant_management_evaluate: Scope value the client uses to request an access token to perform evaluations against its grants.

#### 6.7.2. Evaluation Request

The client sends an HTTP POST request to:
{grant_management_endpoint}/{grant_id}/evaluate

The request body contains:

```
{
  "action": {
    "name": string,
    "properties": object
  },
  "resource": {
    "type": string,
    "id": string,
    "properties": object
  },
  "context": object
}
```

Note: The subject is determined from the OIDC claims in the bearer token, not from the request body.

#### 6.7.3. Evaluation Response

The AS responds with:

```
{
  "decision": boolean,
  "context": {
    "reasons": [
      {string: string}
    ]
  }
}
```

#### 6.7.4. Error Responses

In addition to the standard error responses defined in Section 6.6:

- 400: Invalid evaluation request format
- 401: Invalid/expired subject identifier
- 403: Subject not authorized for this grant
- 422: Missing required resource/location
- 503: Evaluation service unavailable

## [Add to Section 7.1: Authorization server's metadata]

grant_management_actions_supported: Add new supported action:
- evaluate: The AS allows clients to evaluate access against existing grants

grant_evaluation_supported: OPTIONAL. Boolean indicating whether the AS supports grant evaluation.

## [Add new Section 8.4: Grant Evaluation Considerations]

### 8.4. Grant Evaluation Implementation Considerations

#### 8.4.1. Subject Resolution

The AS MUST determine the subject from the the user grant:
- Considering actor claims in delegation scenarios ... TBC
- Supporting both pairwise and public subject identifiers

### 8.4.2. Grant Constraint Application

The AS MUST:
1. Verify the grant is active and not expired
2. Apply all grant constraints (scopes, claims, authorization_details)
3. Consider resource/location accessibility
4. Evaluate any contextual conditions

#### 8.4.3. Response Handling

The AS:
1. MUST provide clear reasons for denied access
2. MUST NOT include administrative or internal reasons
3. SHOULD include relevant context for approval/denial
4. MAY include additional metadata about the evaluation

## [Add to Section 9: Privacy Considerations]

Grant evaluations must maintain the privacy guarantees of OIDC:
- Subject identifiers must be properly scoped to clients
- Evaluation responses must not leak unauthorized information
- Reasons provided must be appropriate for end-user consumption

## [Add to Section 10: Security Considerations]

Grant evaluation introduces additional security considerations:

1. Bearer token validation must be strictly enforced
2. Subject identifier validation must follow OIDC specifications
3. Resource/location access must be properly scoped
4. Rate limiting should be considered for evaluation requests
5. Error responses must not leak sensitive information

## [Add to Appendix A: IANA Considerations]

### A.1. OAuth Parameter Registry additions:

grant_management_evaluate scope
grant_evaluation_supported metadata


## 5. Protected Resource Metadata

Extension to support a new parameter: authorization_enquiry_supported. 
This will signal to the client that it supports the providing of an Authorisation Evaluation in an HTTP Header.
`authorization-evaluation`. 

