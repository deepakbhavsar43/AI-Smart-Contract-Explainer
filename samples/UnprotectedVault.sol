// SPDX-License-Identifier: MIT
// DEMO ONLY - intentionally vulnerable. Do not deploy with real funds.
pragma solidity ^0.8.20;

/// @title UnprotectedVault
/// @notice A treasury vault with several missing access-control checks.
contract UnprotectedVault {
    address public owner;
    address public feeRecipient;
    uint256 public withdrawLimit = 1 ether;
    bool public initialized;

    event OwnerChanged(address indexed newOwner);

    receive() external payable {}

    // BUG: anyone can call this and become owner
    function setOwner(address newOwner) external {
        owner = newOwner;
        emit OwnerChanged(newOwner);
    }

    // BUG: no access control, sends the whole treasury to any address
    function emergencyWithdraw(address payable to) external {
        to.call{value: address(this).balance}("");
    }

    // BUG: tx.origin used for authorization (phishing risk)
    function setWithdrawLimit(uint256 newLimit) external {
        require(tx.origin == owner, "not owner");
        withdrawLimit = newLimit;
    }

    // BUG: no access check on a configuration setter
    function setFeeRecipient(address recipient) external {
        feeRecipient = recipient;
    }

    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        require(amount <= withdrawLimit, "over limit");
        payable(msg.sender).transfer(amount);
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
