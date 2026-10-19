// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {ZkSecureDNARegistry} from "../src/ZkSecureDNARegistry.sol";

/// Deploys the registry. Configure with environment variables:
///   SP1_VERIFIER          address of SP1's verifier gateway on the target chain
///   RECORD_VKEY           record circuit verifying-key hash (bytes32)
///   COMMITTEE_KEY         authority committee threshold key (bytes32)
///   AUTHORITIES           comma-separated authority addresses
///   SHARE_KEYS            comma-separated bytes32 public key shares (same order)
///   THRESHOLD             approvals needed for governance and openings
///   FIELD_COUNT           fields per record (default 6, see zk_escrow::FIELD_NAMES)
///   MAX_RECORD_AGE        seconds (default 7 days)
///
///   forge script script/Deploy.s.sol --rpc-url $RPC --broadcast
/// Screeners are registered afterwards through a governance proposal.
contract Deploy is Script {
    function run() external returns (ZkSecureDNARegistry registry) {
        address[] memory accounts = vm.envAddress("AUTHORITIES", ",");
        bytes32[] memory shareKeys = vm.envBytes32("SHARE_KEYS", ",");
        require(accounts.length == shareKeys.length, "AUTHORITIES and SHARE_KEYS differ in length");

        ZkSecureDNARegistry.InitialAuthority[] memory auths =
            new ZkSecureDNARegistry.InitialAuthority[](accounts.length);
        for (uint256 i = 0; i < accounts.length; i++) {
            auths[i] = ZkSecureDNARegistry.InitialAuthority(accounts[i], uint32(i + 1), shareKeys[i]);
        }

        vm.startBroadcast();
        registry = new ZkSecureDNARegistry(
            ISP1Verifier(vm.envAddress("SP1_VERIFIER")),
            vm.envBytes32("RECORD_VKEY"),
            auths,
            uint32(vm.envUint("THRESHOLD")),
            vm.envBytes32("COMMITTEE_KEY"),
            uint32(vm.envOr("FIELD_COUNT", uint256(6))),
            uint64(vm.envOr("MAX_RECORD_AGE", uint256(7 days)))
        );
        vm.stopBroadcast();
        console.log("ZkSecureDNARegistry deployed at", address(registry));
    }
}
