// SPDX-License-Identifier: MIT
// DEMO ONLY - shows owner powers that users should know about.
pragma solidity ^0.8.20;

/// @title CentralizedToken
/// @notice A minimal ERC-20 where the owner keeps wide powers over holders.
contract CentralizedToken {
    string public name = "Central Token";
    string public symbol = "CTK";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    uint256 public transferFeeBps; // fee in basis points, no upper bound
    address public owner;
    bool public paused;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public isBlacklisted;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        _mint(msg.sender, initialSupply);
    }

    function transfer(address to, uint256 amount) external whenNotPaused returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external whenNotPaused returns (bool) {
        allowance[from][msg.sender] -= amount;
        _transfer(from, to, amount);
        return true;
    }

    // Owner can create unlimited new tokens
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    // Owner can freeze any holder
    function blacklist(address account, bool value) external onlyOwner {
        isBlacklisted[account] = value;
    }

    // Owner can set any fee, up to 100%
    function setTransferFee(uint256 feeBps) external onlyOwner {
        transferFeeBps = feeBps;
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(!isBlacklisted[from] && !isBlacklisted[to], "blacklisted");
        uint256 fee = (amount * transferFeeBps) / 10_000;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
        balanceOf[owner] += fee;
        emit Transfer(from, to, amount - fee);
        if (fee > 0) emit Transfer(from, owner, fee);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}
