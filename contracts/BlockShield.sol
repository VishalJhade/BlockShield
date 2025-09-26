
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BlockShield - Decentralized Identity and Access Management
 * @dev A smart contract system for secure identity verification and access control
 * @author BlockShield Team
 */
contract Project {
    // State variables
    address public owner;
    uint256 public totalUsers;
    uint256 public totalAccessRequests;
    
    // Structs
    struct Identity {
        string name;
        string email;
        bool isVerified;
        bool isActive;
        uint256 registrationTime;
        bytes32 identityHash;
    }
    
    struct AccessRequest {
        address requester;
        address target;
        string resourceId;
        bool isApproved;
        bool isProcessed;
        uint256 requestTime;
        uint256 expiryTime;
    }
    
    // Mappings
    mapping(address => Identity) public identities;
    mapping(address => bool) public verifiers;
    mapping(uint256 => AccessRequest) public accessRequests;
    mapping(address => uint256[]) public userAccessRequests;
    
    // Events
    event IdentityRegistered(address indexed user, string name, uint256 timestamp);
    event IdentityVerified(address indexed user, address indexed verifier, uint256 timestamp);
    event AccessRequested(uint256 indexed requestId, address indexed requester, address indexed target, string resourceId);
    event AccessGranted(uint256 indexed requestId, address indexed approver, uint256 timestamp);
    event AccessRevoked(uint256 indexed requestId, address indexed revoker, uint256 timestamp);
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }
    
    modifier onlyVerifier() {
        require(verifiers[msg.sender] || msg.sender == owner, "Only authorized verifiers can perform this action");
        _;
    }
    
    modifier onlyActiveUser() {
        require(identities[msg.sender].isActive, "User identity must be active");
        _;
    }
    
    constructor() {
        owner = msg.sender;
        verifiers[msg.sender] = true;
        totalUsers = 0;
        totalAccessRequests = 0;
    }
    
    /**
     * @dev Core Function 1: Register a new identity on the blockchain
     * @param _name User's full name
     * @param _email User's email address
     */
    function registerIdentity(string memory _name, string memory _email) external {
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_email).length > 0, "Email cannot be empty");
        require(bytes(identities[msg.sender].name).length == 0, "Identity already exists");
        
        // Create identity hash for privacy
        bytes32 identityHash = keccak256(abi.encodePacked(_name, _email, msg.sender, block.timestamp));
        
        identities[msg.sender] = Identity({
            name: _name,
            email: _email,
            isVerified: false,
            isActive: true,
            registrationTime: block.timestamp,
            identityHash: identityHash
        });
        
        totalUsers++;
        emit IdentityRegistered(msg.sender, _name, block.timestamp);
    }
    
    /**
     * @dev Core Function 2: Verify user identity (only by authorized verifiers)
     * @param _userAddress Address of the user to verify
     */
    function verifyIdentity(address _userAddress) external onlyVerifier {
        require(_userAddress != address(0), "Invalid user address");
        require(bytes(identities[_userAddress].name).length > 0, "Identity does not exist");
        require(!identities[_userAddress].isVerified, "Identity already verified");
        
        identities[_userAddress].isVerified = true;
        emit IdentityVerified(_userAddress, msg.sender, block.timestamp);
    }
    
    /**
     * @dev Core Function 3: Request access to a resource
     * @param _target Address of the resource owner
     * @param _resourceId Identifier of the resource being requested
     * @param _expiryDuration Duration in seconds for which access is requested
     */
    function requestAccess(
        address _target, 
        string memory _resourceId, 
        uint256 _expiryDuration
    ) external onlyActiveUser returns (uint256) {
        require(_target != address(0), "Invalid target address");
        require(bytes(_resourceId).length > 0, "Resource ID cannot be empty");
        require(identities[msg.sender].isVerified, "User must be verified to request access");
        require(_expiryDuration > 0 && _expiryDuration <= 365 days, "Invalid expiry duration");
        
        uint256 requestId = totalAccessRequests;
        uint256 expiryTime = block.timestamp + _expiryDuration;
        
        accessRequests[requestId] = AccessRequest({
            requester: msg.sender,
            target: _target,
            resourceId: _resourceId,
            isApproved: false,
            isProcessed: false,
            requestTime: block.timestamp,
            expiryTime: expiryTime
        });
        
        userAccessRequests[msg.sender].push(requestId);
        totalAccessRequests++;
        
        emit AccessRequested(requestId, msg.sender, _target, _resourceId);
        return requestId;
    }
    
    /**
     * @dev Approve or deny an access request
     * @param _requestId ID of the access request
     * @param _approve True to approve, false to deny
     */
    function processAccessRequest(uint256 _requestId, bool _approve) external {
        require(_requestId < totalAccessRequests, "Invalid request ID");
        AccessRequest storage request = accessRequests[_requestId];
        require(msg.sender == request.target, "Only resource owner can process this request");
        require(!request.isProcessed, "Request already processed");
        require(block.timestamp < request.expiryTime, "Request has expired");
        
        request.isApproved = _approve;
        request.isProcessed = true;
        
        if (_approve) {
            emit AccessGranted(_requestId, msg.sender, block.timestamp);
        } else {
            emit AccessRevoked(_requestId, msg.sender, block.timestamp);
        }
    }
    
    /**
     * @dev Add or remove verifier status
     * @param _verifier Address to modify verifier status
     * @param _status True to add as verifier, false to remove
     */
    function setVerifier(address _verifier, bool _status) external onlyOwner {
        require(_verifier != address(0), "Invalid verifier address");
        verifiers[_verifier] = _status;
    }
    
    /**
     * @dev Get user's access requests
     * @param _user Address of the user
     * @return Array of request IDs
     */
    function getUserAccessRequests(address _user) external view returns (uint256[] memory) {
        return userAccessRequests[_user];
    }
    
    /**
     * @dev Check if user has valid access to a resource
     * @param _user Address of the user
     * @param _requestId Access request ID
     * @return True if access is valid and not expired
     */
    function hasValidAccess(address _user, uint256 _requestId) external view returns (bool) {
        if (_requestId >= totalAccessRequests) return false;
        
        AccessRequest memory request = accessRequests[_requestId];
        return (request.requester == _user && 
                request.isProcessed && 
                request.isApproved && 
                block.timestamp < request.expiryTime);
    }
    
    /**
     * @dev Get identity information (privacy-preserving)
     * @param _user Address of the user
     * @return isVerified Whether the identity is verified
     * @return isActive Whether the identity is active
     * @return registrationTime Timestamp when identity was registered
     * @return identityHash Cryptographic hash of the identity
     */
    function getIdentityInfo(address _user) external view returns (
        bool isVerified, 
        bool isActive, 
        uint256 registrationTime, 
        bytes32 identityHash
    ) {
        Identity memory identity = identities[_user];
        return (identity.isVerified, identity.isActive, identity.registrationTime, identity.identityHash);
    }
}
