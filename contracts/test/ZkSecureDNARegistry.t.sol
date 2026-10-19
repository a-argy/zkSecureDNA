// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {ZkSecureDNARegistry, RecordPublicValues} from "../src/ZkSecureDNARegistry.sol";

/// Registry rules, with SP1's mock verifier (accepts empty proofs). The real
/// Groth16 path is exercised in RecordFixture.t.sol.
contract ZkSecureDNARegistryTest is Test {
    ZkSecureDNARegistry registry;

    address a1 = address(0xA1);
    address a2 = address(0xA2);
    address a3 = address(0xA3);
    address lab = address(0x1AB);

    bytes32 constant SCREENER = keccak256("securedna-main");
    bytes32 constant HDB_KEY = bytes32(uint256(0x11));
    bytes32 constant ASK = bytes32(uint256(0x22));
    bytes32 constant CIRCUITS = bytes32(uint256(0x33));
    bytes32 constant COMMITTEE = bytes32(uint256(0x44));
    uint32 constant FIELDS = 3;

    function setUp() public {
        vm.warp(1_800_000_000);
        ZkSecureDNARegistry.InitialAuthority[] memory auths = new ZkSecureDNARegistry.InitialAuthority[](3);
        auths[0] = ZkSecureDNARegistry.InitialAuthority(a1, 1, bytes32(uint256(1)));
        auths[1] = ZkSecureDNARegistry.InitialAuthority(a2, 2, bytes32(uint256(2)));
        auths[2] = ZkSecureDNARegistry.InitialAuthority(a3, 3, bytes32(uint256(3)));
        registry = new ZkSecureDNARegistry(
            ISP1Verifier(address(new SP1MockVerifier())), bytes32("vk"), auths, 2, COMMITTEE, FIELDS, 7 days
        );
        _govern(
            abi.encodeCall(
                ZkSecureDNARegistry.setScreener,
                (SCREENER, ZkSecureDNARegistry.Screener("SecureDNA", HDB_KEY, ASK, CIRCUITS, true))
            )
        );
    }

    // ---- helpers ------------------------------------------------------------

    function _govern(bytes memory data) internal {
        vm.prank(a1);
        uint256 id = registry.propose(data);
        vm.prank(a2);
        registry.approveProposal(id);
        vm.prank(a1);
        registry.execute(id);
    }

    function _fields(uint256 salt) internal pure returns (bytes[] memory f) {
        f = new bytes[](FIELDS);
        for (uint256 i = 0; i < FIELDS; i++) {
            f[i] = abi.encodePacked(bytes32(uint256(i + 1)), keccak256(abi.encode(salt, i)));
        }
    }

    function _pv(bytes[] memory fields, bytes32 statement) internal view returns (RecordPublicValues memory pv) {
        bytes32[] memory digests = new bytes32[](fields.length);
        for (uint256 i = 0; i < fields.length; i++) {
            digests[i] = sha256(fields[i]);
        }
        pv = RecordPublicValues({
            circuitsDigest: CIRCUITS,
            statementDigest: statement,
            orderCommitment: keccak256("order"),
            activeSecurityKeyDigest: ASK,
            hdbPublicKey: HDB_KEY,
            hazardCount: 0,
            screenedAt: uint64(block.timestamp - 1 hours),
            committeeKey: COMMITTEE,
            fieldDigests: digests
        });
    }

    function _submit(RecordPublicValues memory pv, bytes[] memory fields) internal returns (uint256) {
        vm.prank(lab);
        return registry.submitRecord(SCREENER, abi.encode(pv), "", fields);
    }

    function _record() internal returns (uint256) {
        bytes[] memory f = _fields(1);
        return _submit(_pv(f, keccak256("s1")), f);
    }

    // ---- records ------------------------------------------------------------

    function test_submitRecord_stores_and_indexes_by_lab() public {
        uint256 id = _record();
        ZkSecureDNARegistry.Record memory r = registry.getRecord(id);
        assertEq(r.lab, lab);
        assertEq(r.screenerId, SCREENER);
        assertEq(r.fieldDigests.length, FIELDS);
        assertEq(registry.recordsByLab(lab).length, 1);
        assertTrue(registry.statementUsed(keccak256("s1")));
    }

    function test_rejects_replayed_statement() public {
        _record();
        bytes[] memory f = _fields(2);
        RecordPublicValues memory pv = _pv(f, keccak256("s1"));
        vm.expectRevert(ZkSecureDNARegistry.StatementAlreadyRecorded.selector);
        _submit(pv, f);
    }

    function test_rejects_unknown_or_mismatched_screener() public {
        bytes[] memory f = _fields(1);
        RecordPublicValues memory pv = _pv(f, keccak256("s"));

        vm.prank(lab);
        vm.expectRevert(ZkSecureDNARegistry.UnknownScreener.selector);
        registry.submitRecord(keccak256("other"), abi.encode(pv), "", f);

        pv.hdbPublicKey = bytes32(uint256(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(ZkSecureDNARegistry.ScreenerMismatch.selector, "hdb key"));
        _submit(pv, f);

        pv = _pv(f, keccak256("s"));
        pv.activeSecurityKeyDigest = bytes32(uint256(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(ZkSecureDNARegistry.ScreenerMismatch.selector, "keyservers"));
        _submit(pv, f);

        pv = _pv(f, keccak256("s"));
        pv.circuitsDigest = bytes32(uint256(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(ZkSecureDNARegistry.ScreenerMismatch.selector, "circuits"));
        _submit(pv, f);
    }

    function test_rejects_wrong_committee_key() public {
        bytes[] memory f = _fields(1);
        RecordPublicValues memory pv = _pv(f, keccak256("s"));
        pv.committeeKey = bytes32(uint256(0xBAD));
        vm.expectRevert(ZkSecureDNARegistry.WrongCommitteeKey.selector);
        _submit(pv, f);
    }

    function test_rejects_ciphertext_not_matching_proof() public {
        bytes[] memory f = _fields(1);
        RecordPublicValues memory pv = _pv(f, keccak256("s"));
        f[2] = hex"deadbeef";
        vm.expectRevert(abi.encodeWithSelector(ZkSecureDNARegistry.FieldDigestMismatch.selector, 2));
        _submit(pv, f);
    }

    function test_rejects_wrong_field_count() public {
        bytes[] memory f = _fields(1);
        RecordPublicValues memory pv = _pv(f, keccak256("s"));
        bytes[] memory fewer = new bytes[](2);
        fewer[0] = f[0];
        fewer[1] = f[1];
        vm.expectRevert(ZkSecureDNARegistry.WrongFieldCount.selector);
        _submit(pv, fewer);
    }

    function test_rejects_stale_or_future_screening() public {
        bytes[] memory f = _fields(1);
        RecordPublicValues memory pv = _pv(f, keccak256("s"));
        pv.screenedAt = uint64(block.timestamp - 8 days);
        vm.expectRevert(ZkSecureDNARegistry.ScreeningTooOld.selector);
        _submit(pv, f);
        pv.screenedAt = uint64(block.timestamp + 1 hours);
        vm.expectRevert(ZkSecureDNARegistry.ScreeningInFuture.selector);
        _submit(pv, f);
    }

    function test_rejects_nonempty_proof_with_mock_verifier() public {
        bytes[] memory f = _fields(1);
        RecordPublicValues memory pv = _pv(f, keccak256("s"));
        vm.prank(lab);
        vm.expectRevert();
        registry.submitRecord(SCREENER, abi.encode(pv), hex"01", f);
    }

    function test_rejects_deactivated_screener() public {
        _govern(
            abi.encodeCall(
                ZkSecureDNARegistry.setScreener,
                (SCREENER, ZkSecureDNARegistry.Screener("SecureDNA", HDB_KEY, ASK, CIRCUITS, false))
            )
        );
        bytes[] memory f = _fields(1);
        RecordPublicValues memory pv = _pv(f, keccak256("s"));
        vm.expectRevert(ZkSecureDNARegistry.UnknownScreener.selector);
        _submit(pv, f);
    }

    // ---- investigations -----------------------------------------------------

    function test_case_needs_threshold_before_shares() public {
        uint256 rid = _record();
        vm.prank(a1);
        uint256 cid = registry.openCase(rid, 1, bytes32("recipient"), "ipfs://warrant");
        assertFalse(registry.getCase(cid).authorized);

        vm.prank(a1);
        vm.expectRevert(ZkSecureDNARegistry.CaseNotAuthorized.selector);
        registry.submitDecryptionShare(cid, 0, hex"aa");

        vm.expectEmit(true, true, true, true);
        emit ZkSecureDNARegistry.CaseAuthorized(cid, rid, lab, 1);
        vm.prank(a2);
        registry.approveCase(cid);
        assertTrue(registry.getCase(cid).authorized);

        vm.prank(a1);
        registry.submitDecryptionShare(cid, 0, hex"aa");
        vm.prank(a2);
        registry.submitDecryptionShare(cid, 0, hex"bb");
    }

    function test_case_only_reveals_masked_fields_once_per_authority() public {
        uint256 rid = _record();
        vm.prank(a1);
        uint256 cid = registry.openCase(rid, 4, bytes32("recipient"), "case-7");
        vm.prank(a3);
        registry.approveCase(cid);

        vm.prank(a1);
        vm.expectRevert(ZkSecureDNARegistry.FieldNotInCase.selector);
        registry.submitDecryptionShare(cid, 0, hex"aa");

        vm.prank(a1);
        registry.submitDecryptionShare(cid, 2, hex"aa");
        vm.prank(a1);
        vm.expectRevert(ZkSecureDNARegistry.ShareAlreadySubmitted.selector);
        registry.submitDecryptionShare(cid, 2, hex"aa");

        // a2 did not approve the case, so it cannot contribute.
        vm.prank(a2);
        vm.expectRevert(ZkSecureDNARegistry.NotAuthority.selector);
        registry.submitDecryptionShare(cid, 2, hex"cc");
    }

    function test_case_rules() public {
        uint256 rid = _record();
        vm.prank(lab);
        vm.expectRevert(ZkSecureDNARegistry.NotAuthority.selector);
        registry.openCase(rid, 1, bytes32(0), "");

        vm.startPrank(a1);
        vm.expectRevert(ZkSecureDNARegistry.EmptyFieldMask.selector);
        registry.openCase(rid, 0, bytes32(0), "");
        vm.expectRevert(ZkSecureDNARegistry.FieldNotInCase.selector);
        registry.openCase(rid, 1 << FIELDS, bytes32(0), "");
        vm.expectRevert(ZkSecureDNARegistry.NotFound.selector);
        registry.openCase(99, 1, bytes32(0), "");
        uint256 cid = registry.openCase(rid, 1, bytes32(0), "");
        vm.expectRevert(ZkSecureDNARegistry.AlreadyApproved.selector);
        registry.approveCase(cid);
        vm.stopPrank();
    }

    // ---- governance ---------------------------------------------------------

    function test_governance_functions_need_a_passed_proposal() public {
        vm.prank(a1);
        vm.expectRevert(ZkSecureDNARegistry.OnlyGovernance.selector);
        registry.setCommitteeKey(bytes32(uint256(5)));

        vm.prank(a1);
        uint256 pid = registry.propose(abi.encodeCall(ZkSecureDNARegistry.setCommitteeKey, (bytes32(uint256(5)))));
        vm.prank(a1);
        vm.expectRevert(ZkSecureDNARegistry.NotEnoughApprovals.selector);
        registry.execute(pid);

        vm.prank(a3);
        registry.approveProposal(pid);
        vm.prank(a3);
        registry.execute(pid);
        assertEq(registry.committeeKey(), bytes32(uint256(5)));
        assertEq(registry.committeeEpoch(), 2);

        vm.prank(a3);
        vm.expectRevert(ZkSecureDNARegistry.AlreadyExecuted.selector);
        registry.execute(pid);
    }

    function test_committee_rotation_applies_to_new_records_only() public {
        uint256 rid = _record();
        _govern(abi.encodeCall(ZkSecureDNARegistry.setCommitteeKey, (bytes32(uint256(5)))));
        assertEq(registry.getRecord(rid).committeeKey, COMMITTEE);
        bytes[] memory f = _fields(3);
        RecordPublicValues memory pv = _pv(f, keccak256("s3"));
        vm.expectRevert(ZkSecureDNARegistry.WrongCommitteeKey.selector);
        _submit(pv, f);
    }

    function test_authority_membership_and_threshold() public {
        address a4 = address(0xA4);
        _govern(abi.encodeCall(ZkSecureDNARegistry.addAuthority, (a4, 4, bytes32(uint256(4)))));
        assertTrue(registry.isAuthority(a4));
        _govern(abi.encodeCall(ZkSecureDNARegistry.setThreshold, (3)));
        assertEq(registry.threshold(), 3);

        // Removing members below the threshold fails (the proposal reverts).
        vm.prank(a1);
        uint256 pid = registry.propose(abi.encodeCall(ZkSecureDNARegistry.setThreshold, (5)));
        vm.prank(a2);
        registry.approveProposal(pid);
        vm.prank(a3);
        registry.approveProposal(pid);
        vm.prank(a1);
        vm.expectRevert();
        registry.execute(pid);

        _governAs3(abi.encodeCall(ZkSecureDNARegistry.removeAuthority, (a4)));
        assertFalse(registry.isAuthority(a4));
        assertEq(registry.authorities().length, 3);
    }

    function _governAs3(bytes memory data) internal {
        vm.prank(a1);
        uint256 id = registry.propose(data);
        vm.prank(a2);
        registry.approveProposal(id);
        vm.prank(a3);
        registry.approveProposal(id);
        vm.prank(a1);
        registry.execute(id);
    }

    function test_non_authorities_cannot_propose_or_approve() public {
        vm.prank(lab);
        vm.expectRevert(ZkSecureDNARegistry.NotAuthority.selector);
        registry.propose("");
        vm.prank(a1);
        uint256 pid = registry.propose("");
        vm.prank(lab);
        vm.expectRevert(ZkSecureDNARegistry.NotAuthority.selector);
        registry.approveProposal(pid);
    }
}
