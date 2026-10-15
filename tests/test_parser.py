from pathlib import Path

from app.parser import mask_source, parse_sources, pick_main_contract

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_mask_preserves_offsets_and_newlines():
    src = 'uint a = 1; // comment {\n/* block { \n } */ string s = "a{b}";\n'
    masked = mask_source(src)
    assert len(masked) == len(src)
    assert masked.count("\n") == src.count("\n")
    assert "{" not in masked and "}" not in masked  # braces in comments/strings are hidden


def test_splits_functions_with_line_numbers():
    src = (SAMPLES / "VulnerableBank.sol").read_text()
    parsed = parse_sources([("VulnerableBank.sol", src)])
    c = parsed.contract("VulnerableBank")
    names = [f.name for f in c.functions]
    assert names == ["constructor", "deposit", "withdraw", "balanceOf"]
    withdraw = next(f for f in c.functions if f.name == "withdraw")
    lines = src.split("\n")
    assert "function withdraw()" in lines[withdraw.start_line - 1]
    assert lines[withdraw.end_line - 1].strip() == "}"
    assert withdraw.visibility == "external"
    assert {v.name for v in c.state_vars} == {"balances", "totalDeposits", "owner"}


def test_modifiers_visibility_and_mutability():
    src = """
    contract T {
        address owner;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function a(uint x) external payable onlyOwner returns (uint) { return x; }
        function b() public view virtual override(A, B) returns (uint) { return 1; }
        function c() { }
        function d() external;
    }"""
    c = parse_sources([("T.sol", src)]).contract("T")
    fns = {f.name: f for f in c.functions}
    assert fns["a"].modifiers == ["onlyOwner"] and fns["a"].mutability == "payable"
    assert fns["b"].modifiers == [] and fns["b"].mutability == "view"
    assert fns["c"].visibility == "public"  # pre-0.5 default
    assert fns["d"].has_body is False
    assert fns["onlyOwner"].kind == "modifier"


def test_inheritance_and_main_contract():
    src = """
    interface IERC20 { function transfer(address, uint) external returns (bool); }
    abstract contract Base { uint256 internal x; }
    contract Child is Base, IERC20 { function transfer(address, uint) external returns (bool) { x = 1; return true; } }
    """
    parsed = parse_sources([("C.sol", src)])
    main = pick_main_contract(parsed)
    assert main.name == "Child"
    assert [c.name for c in parsed.lineage("Child")] == ["Child", "Base", "IERC20"]
    assert "x" in parsed.state_var_names("Child")


def test_legacy_constructor_and_mapping_state_vars():
    src = """
    contract Old {
        mapping (address => mapping (address => uint)) public allowance;
        uint constant FEE = 10;
        function Old() public { }
    }"""
    c = parse_sources([("Old.sol", src)]).contract("Old")
    assert c.functions[0].kind == "constructor"
    vars_ = {v.name: v for v in c.state_vars}
    assert "allowance" in vars_ and vars_["FEE"].constant
