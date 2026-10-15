// SPDX-License-Identifier: MIT
// DEMO ONLY - intentionally vulnerable. Do not deploy with real funds.
pragma solidity ^0.8.20;

/// @title VulnerableBank
/// @notice A simple ETH savings bank with a classic reentrancy bug.
contract VulnerableBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    address public owner;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "nothing sent");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Withdraw your whole balance.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");

        // BUG: external call happens before the balance is cleared
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] = 0;
        totalDeposits -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }
}
