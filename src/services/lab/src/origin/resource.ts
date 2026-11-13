// Authored research content for the existing fixed protected route.
// Preserve the established 1024-byte response envelope used by lab consumers.
const brief = `TOKENFORGE RESEARCH BRIEF 01
Shared egress and fair access

Research question
How can independently admitted clients share a proxy without sharing one
authorization allowance?

Method
Give each laboratory client the same entitlement budget. Send an abusive
client's attempts first, then the honest clients' requests. Count protected
origin arrivals independently of the client display. Reset between profiles.

Evidence to collect
Accepted and refused requests, replay outcomes, issuance bytes, preparation
time and complete response latency. Record uncertain delivery and failures.

Interpretation
A spent authorization may remain spent when its response is lost. Enrollment
defines the entitlement budget. Transport metadata and host trust remain
part of the experiment's assumptions.

Protocol references
https://www.rfc-editor.org/rfc/rfc9578
https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/01/

TokenForge laboratory research resource. Revision 1.
`;

export const RESEARCH_RESOURCE_BODY = Buffer.from(brief.padEnd(1024, '\n'), 'utf8');
