// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @notice Public values of the zkSecureDNA record circuit
/// (zk/programs/record). Field order and types must match exactly.
struct RecordPublicValues {
    bytes32 circuitsDigest;
    bytes32 statementDigest;
    bytes32 orderCommitment;
    bytes32 activeSecurityKeyDigest;
    bytes32 hdbPublicKey;
    bytes32 hdbRoot;
    uint32 hazardCount;
    uint32 lookupHits;
    uint64 screenedAt;
    bytes32 committeeKey;
    bytes32[] fieldDigests;
}

/// @title zkSecureDNA registry
/// @notice Voluntary, privacy-preserving records of DNA synthesis screening.
///
/// A lab submits a record: an SP1 proof that (a) an order was screened by a
/// registered screening service following its protocol, (b) the service
/// attested to the outcome, and proved every database lookup against a
/// published root of its hazard database, and (c) the record's fields (the screened sequence
/// windows plus metadata such as purpose and lab id) are encrypted to the
/// authority committee's threshold key. Nothing in a record is readable by
/// anyone, including any single authority.
///
/// Registered authorities (e.g. public-health agencies) govern the registry
/// and handle investigations: any `threshold` of them can authorize opening
/// selected fields of one record. Authorization is public and emits an event
/// indexed by the lab, so every opening is visible. Authorities then send
/// their decryption shares, encrypted to the case's recipient key; the
/// shares are verified and combined off chain (crates/zk_escrow).
contract ZkSecureDNARegistry {
    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------

    /// A screening protocol + service the registry accepts records from.
    struct Screener {
        string name;
        bytes32 hdbPublicKey; // Ed25519 key that signs attestations
        bytes32 activeSecurityKeyDigest; // pins the service's keyservers
        bytes32 circuitsDigest; // pins the screening circuits
        address curator; // publishes the hazard database's Merkle trie roots
        bool active;
    }

    struct Record {
        address lab;
        bytes32 screenerId;
        bytes32 statementDigest;
        bytes32 orderCommitment;
        bytes32 committeeKey;
        bytes32 hdbRoot;
        uint32 hazardCount;
        uint32 lookupHits; // screened hashes the lookup proofs found in the database
        uint64 screenedAt;
        uint64 submittedAt;
        bytes32[] fieldDigests;
    }

    struct Proposal {
        bytes data; // calldata for a governance function on this contract
        address proposer;
        uint64 createdAt;
        uint32 approvals;
        bool executed;
    }

    struct Case {
        uint256 recordId;
        uint256 fieldMask; // bit i => field i may be opened
        bytes32 recipientKey; // Ristretto key the shares are encrypted to
        string reasonURI; // legal basis / warrant reference
        address opener;
        uint64 openedAt;
        uint32 approvals;
        bool authorized;
    }

    // ---------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------

    ISP1Verifier public immutable verifier;

    /// Verifying-key hash of the record circuit.
    bytes32 public recordProgramVKey;
    /// Threshold encryption key of the authority committee.
    bytes32 public committeeKey;
    uint32 public committeeEpoch;
    /// Number of encrypted fields every record must carry (field 0 = windows).
    uint32 public requiredFieldCount;
    /// Maximum age of a screening (from the service's attestation) at submission.
    uint64 public maxRecordAge;

    address[] internal _authorities;
    mapping(address => bool) public isAuthority;
    /// Shamir x-coordinate and public key share of each authority, used off
    /// chain to verify its decryption shares.
    mapping(address => uint32) public authorityShareIndex;
    mapping(address => bytes32) public authorityShareKey;
    uint32 public threshold;

    mapping(bytes32 => Screener) internal _screeners;
    /// When each hazard-database root was published, per screener (0 = never).
    /// Every root ever published stays listed, so all labs and auditors see
    /// the same database versions.
    mapping(bytes32 => mapping(bytes32 => uint64)) public hdbRootPublishedAt;
    mapping(bytes32 => mapping(bytes32 => bool)) public hdbRootRevoked;

    Record[] internal _records;
    mapping(bytes32 => bool) public statementUsed;
    mapping(address => uint256[]) internal _recordsByLab;

    Proposal[] internal _proposals;
    mapping(uint256 => mapping(address => bool)) public proposalApprovedBy;

    Case[] internal _cases;
    mapping(uint256 => mapping(address => bool)) public caseApprovedBy;
    mapping(uint256 => mapping(address => uint256)) public caseSharesSubmitted;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event RecordSubmitted(
        uint256 indexed recordId,
        address indexed lab,
        bytes32 indexed screenerId,
        bytes32 statementDigest,
        uint32 hazardCount,
        uint32 lookupHits,
        uint64 screenedAt,
        bytes[] encryptedFields
    );
    event ProposalCreated(uint256 indexed proposalId, address indexed proposer, bytes data);
    event ProposalApproved(uint256 indexed proposalId, address indexed authority, uint32 approvals);
    event ProposalExecuted(uint256 indexed proposalId);
    event CaseOpened(
        uint256 indexed caseId, uint256 indexed recordId, address indexed lab, uint256 fieldMask, address opener, string reasonURI
    );
    event CaseApproved(uint256 indexed caseId, address indexed authority, uint32 approvals);
    /// The public notice that a record is being opened.
    event CaseAuthorized(uint256 indexed caseId, uint256 indexed recordId, address indexed lab, uint256 fieldMask);
    event DecryptionShareSubmitted(
        uint256 indexed caseId, uint32 indexed field, address indexed authority, bytes encryptedShare
    );
    event ScreenerSet(bytes32 indexed screenerId, string name, bool active);
    event HdbRootPublished(bytes32 indexed screenerId, bytes32 indexed root);
    event HdbRootRevoked(bytes32 indexed screenerId, bytes32 indexed root);
    event AuthorityAdded(address indexed authority, uint32 shareIndex, bytes32 shareKey);
    event AuthorityRemoved(address indexed authority);
    event ThresholdSet(uint32 threshold);
    event CommitteeKeySet(bytes32 committeeKey, uint32 epoch);
    event RecordProgramSet(bytes32 vkey);
    event RecordRulesSet(uint32 requiredFieldCount, uint64 maxRecordAge);

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    error NotAuthority();
    error OnlyGovernance();
    error UnknownScreener();
    error UnknownHdbRoot();
    error NotCurator();
    error ScreenerMismatch(string what);
    error WrongCommitteeKey();
    error WrongFieldCount();
    error FieldDigestMismatch(uint256 field);
    error StatementAlreadyRecorded();
    error ScreeningTooOld();
    error ScreeningInFuture();
    error NotFound();
    error AlreadyApproved();
    error AlreadyExecuted();
    error NotEnoughApprovals();
    error ExecutionFailed(bytes reason);
    error InvalidThreshold();
    error InvalidAuthority();
    error CaseNotAuthorized();
    error FieldNotInCase();
    error ShareAlreadySubmitted();
    error EmptyFieldMask();

    // ---------------------------------------------------------------------
    // Setup
    // ---------------------------------------------------------------------

    struct InitialAuthority {
        address account;
        uint32 shareIndex;
        bytes32 shareKey;
    }

    constructor(
        ISP1Verifier verifier_,
        bytes32 recordProgramVKey_,
        InitialAuthority[] memory authorities_,
        uint32 threshold_,
        bytes32 committeeKey_,
        uint32 requiredFieldCount_,
        uint64 maxRecordAge_
    ) {
        verifier = verifier_;
        recordProgramVKey = recordProgramVKey_;
        emit RecordProgramSet(recordProgramVKey_);
        for (uint256 i = 0; i < authorities_.length; i++) {
            _addAuthority(authorities_[i].account, authorities_[i].shareIndex, authorities_[i].shareKey);
        }
        _setThreshold(threshold_);
        _setCommitteeKey(committeeKey_);
        _setRecordRules(requiredFieldCount_, maxRecordAge_);
    }

    modifier onlyAuthority() {
        if (!isAuthority[msg.sender]) revert NotAuthority();
        _;
    }

    /// Governance functions are only callable through an executed proposal.
    modifier onlyGovernance() {
        if (msg.sender != address(this)) revert OnlyGovernance();
        _;
    }

    // ---------------------------------------------------------------------
    // Records
    // ---------------------------------------------------------------------

    /// @notice Submit a screening record.
    /// @param screenerId The registered screening service that screened the order.
    /// @param publicValues ABI-encoded RecordPublicValues committed by the record circuit.
    /// @param proof SP1 Groth16 proof bytes for the record circuit.
    /// @param encryptedFields `R ‖ ciphertext` per field; field i must hash
    ///        (SHA-256) to `fieldDigests[i]`. Published in the event only.
    function submitRecord(
        bytes32 screenerId,
        bytes calldata publicValues,
        bytes calldata proof,
        bytes[] calldata encryptedFields
    ) external returns (uint256 recordId) {
        verifier.verifyProof(recordProgramVKey, publicValues, proof);
        RecordPublicValues memory pv = abi.decode(publicValues, (RecordPublicValues));

        Screener storage s = _screeners[screenerId];
        if (!s.active) revert UnknownScreener();
        if (pv.hdbPublicKey != s.hdbPublicKey) revert ScreenerMismatch("hdb key");
        if (pv.activeSecurityKeyDigest != s.activeSecurityKeyDigest) revert ScreenerMismatch("keyservers");
        if (pv.circuitsDigest != s.circuitsDigest) revert ScreenerMismatch("circuits");
        if (hdbRootPublishedAt[screenerId][pv.hdbRoot] == 0 || hdbRootRevoked[screenerId][pv.hdbRoot]) {
            revert UnknownHdbRoot();
        }
        if (pv.committeeKey != committeeKey) revert WrongCommitteeKey();
        if (pv.screenedAt > block.timestamp + 5 minutes) revert ScreeningInFuture();
        if (pv.screenedAt + maxRecordAge < block.timestamp) revert ScreeningTooOld();

        uint256 n = pv.fieldDigests.length;
        if (n != requiredFieldCount || encryptedFields.length != n) revert WrongFieldCount();
        for (uint256 i = 0; i < n; i++) {
            if (sha256(encryptedFields[i]) != pv.fieldDigests[i]) revert FieldDigestMismatch(i);
        }

        if (statementUsed[pv.statementDigest]) revert StatementAlreadyRecorded();
        statementUsed[pv.statementDigest] = true;

        recordId = _records.length;
        _records.push(
            Record({
                lab: msg.sender,
                screenerId: screenerId,
                statementDigest: pv.statementDigest,
                orderCommitment: pv.orderCommitment,
                committeeKey: pv.committeeKey,
                hdbRoot: pv.hdbRoot,
                hazardCount: pv.hazardCount,
                lookupHits: pv.lookupHits,
                screenedAt: pv.screenedAt,
                submittedAt: uint64(block.timestamp),
                fieldDigests: pv.fieldDigests
            })
        );
        _recordsByLab[msg.sender].push(recordId);
        emit RecordSubmitted(
            recordId, msg.sender, screenerId, pv.statementDigest, pv.hazardCount, pv.lookupHits, pv.screenedAt, encryptedFields
        );
    }

    function recordCount() external view returns (uint256) {
        return _records.length;
    }

    function getRecord(uint256 recordId) external view returns (Record memory) {
        if (recordId >= _records.length) revert NotFound();
        return _records[recordId];
    }

    function recordsByLab(address lab) external view returns (uint256[] memory) {
        return _recordsByLab[lab];
    }

    function getScreener(bytes32 screenerId) external view returns (Screener memory) {
        return _screeners[screenerId];
    }

    /// @notice Publish a root of the screener's hazard database (its Merkle
    /// trie, crates/hdb_trie). Records can only use published roots. The
    /// curator vouches that the root is the real database: anyone holding the
    /// database can rebuild the root and check it.
    function publishHdbRoot(bytes32 screenerId, bytes32 root) external {
        Screener storage s = _screeners[screenerId];
        if (!s.active) revert UnknownScreener();
        if (msg.sender != s.curator) revert NotCurator();
        if (hdbRootPublishedAt[screenerId][root] == 0) {
            hdbRootPublishedAt[screenerId][root] = uint64(block.timestamp);
            emit HdbRootPublished(screenerId, root);
        }
    }

    function authorities() external view returns (address[] memory) {
        return _authorities;
    }

    // ---------------------------------------------------------------------
    // Investigations
    // ---------------------------------------------------------------------

    /// @notice Open a case to reveal `fieldMask` fields of one record. The
    /// opener's approval counts; nothing is revealed until `threshold`
    /// authorities approve.
    function openCase(uint256 recordId, uint256 fieldMask, bytes32 recipientKey, string calldata reasonURI)
        external
        onlyAuthority
        returns (uint256 caseId)
    {
        if (recordId >= _records.length) revert NotFound();
        if (fieldMask == 0) revert EmptyFieldMask();
        uint256 fieldCount = _records[recordId].fieldDigests.length;
        if (fieldCount < 256 && fieldMask >> fieldCount != 0) revert FieldNotInCase();

        caseId = _cases.length;
        _cases.push(
            Case({
                recordId: recordId,
                fieldMask: fieldMask,
                recipientKey: recipientKey,
                reasonURI: reasonURI,
                opener: msg.sender,
                openedAt: uint64(block.timestamp),
                approvals: 0,
                authorized: false
            })
        );
        emit CaseOpened(caseId, recordId, _records[recordId].lab, fieldMask, msg.sender, reasonURI);
        _approveCase(caseId);
    }

    function approveCase(uint256 caseId) external onlyAuthority {
        if (caseId >= _cases.length) revert NotFound();
        _approveCase(caseId);
    }

    function _approveCase(uint256 caseId) internal {
        if (caseApprovedBy[caseId][msg.sender]) revert AlreadyApproved();
        caseApprovedBy[caseId][msg.sender] = true;
        Case storage c = _cases[caseId];
        c.approvals += 1;
        emit CaseApproved(caseId, msg.sender, c.approvals);
        if (!c.authorized && c.approvals >= threshold) {
            c.authorized = true;
            emit CaseAuthorized(caseId, c.recordId, _records[c.recordId].lab, c.fieldMask);
        }
    }

    /// @notice An authority posts its decryption share for one field of an
    /// authorized case, encrypted to the case's recipient key (see
    /// zk_escrow::DecryptionShare). Only approving authorities may contribute.
    function submitDecryptionShare(uint256 caseId, uint32 field, bytes calldata encryptedShare)
        external
        onlyAuthority
    {
        if (caseId >= _cases.length) revert NotFound();
        Case storage c = _cases[caseId];
        if (!c.authorized) revert CaseNotAuthorized();
        if (!caseApprovedBy[caseId][msg.sender]) revert NotAuthority();
        if (field >= 256 || (c.fieldMask >> field) & 1 == 0) revert FieldNotInCase();
        uint256 bit = uint256(1) << field;
        if (caseSharesSubmitted[caseId][msg.sender] & bit != 0) revert ShareAlreadySubmitted();
        caseSharesSubmitted[caseId][msg.sender] |= bit;
        emit DecryptionShareSubmitted(caseId, field, msg.sender, encryptedShare);
    }

    function caseCount() external view returns (uint256) {
        return _cases.length;
    }

    function getCase(uint256 caseId) external view returns (Case memory) {
        if (caseId >= _cases.length) revert NotFound();
        return _cases[caseId];
    }

    // ---------------------------------------------------------------------
    // Governance: threshold-of-authorities proposals calling this contract
    // ---------------------------------------------------------------------

    function propose(bytes calldata data) external onlyAuthority returns (uint256 proposalId) {
        proposalId = _proposals.length;
        _proposals.push(
            Proposal({data: data, proposer: msg.sender, createdAt: uint64(block.timestamp), approvals: 0, executed: false})
        );
        emit ProposalCreated(proposalId, msg.sender, data);
        _approveProposal(proposalId);
    }

    function approveProposal(uint256 proposalId) external onlyAuthority {
        if (proposalId >= _proposals.length) revert NotFound();
        _approveProposal(proposalId);
    }

    function _approveProposal(uint256 proposalId) internal {
        if (proposalApprovedBy[proposalId][msg.sender]) revert AlreadyApproved();
        proposalApprovedBy[proposalId][msg.sender] = true;
        Proposal storage p = _proposals[proposalId];
        p.approvals += 1;
        emit ProposalApproved(proposalId, msg.sender, p.approvals);
    }

    function execute(uint256 proposalId) external onlyAuthority {
        if (proposalId >= _proposals.length) revert NotFound();
        Proposal storage p = _proposals[proposalId];
        if (p.executed) revert AlreadyExecuted();
        if (p.approvals < threshold) revert NotEnoughApprovals();
        p.executed = true;
        (bool ok, bytes memory reason) = address(this).call(p.data);
        if (!ok) revert ExecutionFailed(reason);
        emit ProposalExecuted(proposalId);
    }

    function getProposal(uint256 proposalId) external view returns (Proposal memory) {
        if (proposalId >= _proposals.length) revert NotFound();
        return _proposals[proposalId];
    }

    function setScreener(bytes32 screenerId, Screener calldata screener) external onlyGovernance {
        _screeners[screenerId] = screener;
        emit ScreenerSet(screenerId, screener.name, screener.active);
    }

    /// Withdraws a root (e.g. a database later found to be missing entries).
    function revokeHdbRoot(bytes32 screenerId, bytes32 root) external onlyGovernance {
        hdbRootRevoked[screenerId][root] = true;
        emit HdbRootRevoked(screenerId, root);
    }

    function addAuthority(address account, uint32 shareIndex, bytes32 shareKey) external onlyGovernance {
        _addAuthority(account, shareIndex, shareKey);
    }

    function removeAuthority(address account) external onlyGovernance {
        if (!isAuthority[account]) revert InvalidAuthority();
        isAuthority[account] = false;
        delete authorityShareIndex[account];
        delete authorityShareKey[account];
        for (uint256 i = 0; i < _authorities.length; i++) {
            if (_authorities[i] == account) {
                _authorities[i] = _authorities[_authorities.length - 1];
                _authorities.pop();
                break;
            }
        }
        if (threshold > _authorities.length) revert InvalidThreshold();
        emit AuthorityRemoved(account);
    }

    function setThreshold(uint32 threshold_) external onlyGovernance {
        _setThreshold(threshold_);
    }

    /// Rotating the committee key (e.g. after membership changes) applies to
    /// new records; existing records stay encrypted to the key they used.
    function setCommitteeKey(bytes32 committeeKey_) external onlyGovernance {
        _setCommitteeKey(committeeKey_);
    }

    function setRecordProgram(bytes32 vkey) external onlyGovernance {
        recordProgramVKey = vkey;
        emit RecordProgramSet(vkey);
    }

    function setRecordRules(uint32 requiredFieldCount_, uint64 maxRecordAge_) external onlyGovernance {
        _setRecordRules(requiredFieldCount_, maxRecordAge_);
    }

    function _addAuthority(address account, uint32 shareIndex, bytes32 shareKey) internal {
        if (account == address(0) || isAuthority[account] || shareIndex == 0) revert InvalidAuthority();
        isAuthority[account] = true;
        authorityShareIndex[account] = shareIndex;
        authorityShareKey[account] = shareKey;
        _authorities.push(account);
        emit AuthorityAdded(account, shareIndex, shareKey);
    }

    function _setThreshold(uint32 threshold_) internal {
        if (threshold_ == 0 || threshold_ > _authorities.length) revert InvalidThreshold();
        threshold = threshold_;
        emit ThresholdSet(threshold_);
    }

    function _setCommitteeKey(bytes32 committeeKey_) internal {
        committeeKey = committeeKey_;
        committeeEpoch += 1;
        emit CommitteeKeySet(committeeKey_, committeeEpoch);
    }

    function _setRecordRules(uint32 requiredFieldCount_, uint64 maxRecordAge_) internal {
        if (requiredFieldCount_ == 0) revert WrongFieldCount();
        requiredFieldCount = requiredFieldCount_;
        maxRecordAge = maxRecordAge_;
        emit RecordRulesSet(requiredFieldCount_, maxRecordAge_);
    }
}
