// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

abstract contract OwnableBootstrap {
    error NotBootstrapOwner();
    error ZeroAddress();

    address public immutable bootstrapOwner;

    constructor(address initialBootstrapOwner) {
        if (initialBootstrapOwner == address(0)) revert ZeroAddress();
        bootstrapOwner = initialBootstrapOwner;
    }

    modifier onlyBootstrapOwner() {
        if (msg.sender != bootstrapOwner) revert NotBootstrapOwner();
        _;
    }
}
