from pathlib import Path

from app.parser import parse_sources
from app.static_checks import run_static_checks

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def findings_for(src: str, name: str = "T.sol"):
    parsed = parse_sources([(name, src)])
    fns = [f for c in parsed.contracts for f in c.functions if f.has_body]
    return run_static_checks(parsed, fns)


def sample(name: str):
    return findings_for((SAMPLES / f"{name}.sol").read_text(), f"{name}.sol")


def rules(findings):
    return {(f.function_name, f.rule) for f in findings}


def test_reentrancy_detected_with_cited_lines():
    src = (SAMPLES / "VulnerableBank.sol").read_text()
    fs = sample("VulnerableBank")
    assert ("withdraw", "reentrancy-state-write-after-call") in rules(fs)
    f = next(f for f in fs if f.category == "reentrancy")
    lines = src.split("\n")
    assert ".call{value: amount}" in lines[f.lines[0] - 1]
    assert "balances[msg.sender] = 0" in lines[f.lines[1] - 1]
    assert f.severity == "high"


def test_fixed_bank_is_clean():
    assert sample("SafeBank") == []


def test_reentrancy_guard_suppresses_finding():
    src = """contract T { mapping(address=>uint) b;
      function w() external nonReentrant { (bool ok,) = msg.sender.call{value: b[msg.sender]}(""); require(ok); b[msg.sender] = 0; } }"""
    assert not [f for f in findings_for(src) if f.category == "reentrancy"]


def test_missing_access_control_cases():
    r = rules(sample("UnprotectedVault"))
    assert ("setOwner", "unprotected-privileged-write") in r
    assert ("destroy", "unprotected-selfdestruct") in r
    assert ("emergencyWithdraw", "unprotected-funds-transfer") in r
    assert ("emergencyWithdraw", "unchecked-low-level-call") in r
    assert ("setWithdrawLimit", "tx-origin-auth") in r
    assert ("setFeeRecipient", "sensitive-function-no-access-control") in r
    # owner-checked withdraw is not an access-control bug
    assert ("withdraw", "sensitive-function-no-access-control") not in r


def test_owner_powers():
    r = rules(sample("CentralizedToken"))
    assert ("mint", "owner-power-mint") in r
    assert ("blacklist", "owner-power-blacklist") in r
    assert ("setTransferFee", "owner-power-fee") in r
    assert ("pause", "owner-power-pause") in r
    # ordinary user functions are not flagged
    assert not any(name in {"transfer", "approve", "transferFrom"} for name, _ in r)


def test_bounded_fee_is_low_severity():
    src = """contract T { address owner; uint fee; modifier onlyOwner(){require(msg.sender==owner);_;}
      function setFee(uint f) external onlyOwner { require(f <= 500, "max 5%"); fee = f; } }"""
    f = [x for x in findings_for(src) if x.rule == "owner-power-fee"][0]
    assert f.severity == "low"


def test_user_scoped_setter_not_flagged():
    src = """contract T { mapping(address=>mapping(address=>bool)) ops;
      function setApprovalForAll(address o, bool v) external { ops[msg.sender][o] = v; } }"""
    assert findings_for(src) == []


def test_token_transfer_before_write_is_medium_reentrancy():
    src = """interface IERC20 { function transfer(address,uint) external returns (bool); }
    contract T { IERC20 token; mapping(address=>uint) owed;
      function claim() external { token.transfer(msg.sender, owed[msg.sender]); owed[msg.sender] = 0; } }"""
    fs = [f for f in findings_for(src) if f.category == "reentrancy"]
    assert fs and fs[0].severity == "medium"


def test_allowance_check_is_not_treated_as_auth():
    from app.analyzer import who_can_call
    src = """contract W { mapping(address=>uint) public balanceOf; mapping(address=>mapping(address=>uint)) public allowance;
      function transferFrom(address src, address dst, uint wad) public returns (bool) {
        if (src != msg.sender) { allowance[src][msg.sender] -= wad; }
        balanceOf[src] -= wad; balanceOf[dst] += wad; return true; } }"""
    parsed = parse_sources([("W.sol", src)])
    fn = parsed.contract("W").functions[0]
    assert who_can_call(fn, parsed.state_var_names("W")) == "Anyone"
