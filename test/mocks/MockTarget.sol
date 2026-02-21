// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockTarget {
    uint256 public number;
    bytes32 public lastTag;

    event NumberSet(uint256 value);

    function setNumber(uint256 value, bytes32 tag) external {
        number = value;
        lastTag = tag;
        emit NumberSet(value);
    }
}
