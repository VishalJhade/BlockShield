🛡️ BlockShield Project Overview
BlockShield is a decentralized identity and access management system that provides secure, blockchain-based identity verification and resource access control.
Core Smart Contract Features:

🆔 Identity Registration (registerIdentity)

Users can register their identity with name and email
Creates a privacy-preserving identity hash
Tracks registration time and user status


✅ Identity Verification (verifyIdentity)

Authorized verifiers can validate user identities
Only owner and designated verifiers can perform verification
Emits verification events for transparency


🚪 Access Control (requestAccess)

Verified users can request access to resources
Time-limited access with automatic expiry
Resource owners can approve/deny requests



Additional Security Features:

Role-based access control (Owner, Verifier, User)
Identity privacy through cryptographic hashing
Comprehensive event logging
Time-based access expiration
Request validation and status tracking
