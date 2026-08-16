import json
import pytest


def test_critical_threat_adjudication_and_circuit_breaker(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """
    Test complete lifecycle of SentinAI:
    1. Alice registers a DeFi vault (0xVault...) with 40 GEN bounty pool.
    2. Bob (Whitehat) detects active exploit and submits a threat report with 1 GEN stake.
    3. GenLayer validators fetch live exploit evidence, reach consensus on CRITICAL threat (conf: 96),
       trigger the emergency pause circuit-breaker, and award 10 GEN bounty (25% pool) + 1 GEN stake refund to Bob.
    """
    contract = direct_deploy("contracts/sentinai.py")
    vault_address = "0x1111111111111111111111111111111111111111"

    # Step 1: Alice registers vault with 40 GEN bounty
    direct_vm.sender = direct_alice
    direct_vm.value = 40 * 10**18
    contract.register_vault(vault_address)

    v_init = contract.get_vault(vault_address)
    assert v_init["owner"].lower() == str(direct_alice).lower()
    assert v_init["bounty_pool"] == str(40 * 10**18)
    assert v_init["is_paused"] is False
    assert v_init["total_reports"] == 0

    # Step 2: Mock live web advisory from security firm
    direct_vm.mock_web(
        r".*github\.com/advisories/.*",
        {
            "status": 200,
            "body": json.dumps({
                "ghsa_id": "GHSA-xxxx-yyyy",
                "severity": "CRITICAL",
                "summary": "Reentrancy in depositYield function allows arbitrary draining of vault balance.",
                "affected_contracts": [vault_address],
            }),
        },
    )

    # Mock LLM threat classification
    direct_vm.mock_llm(
        r".*SentinAI Web3 Threat Oracle.*",
        json.dumps({
            "threat_level": "CRITICAL",
            "confidence_score": 96,
            "should_pause": True,
            "rationale": "Active reentrancy vulnerability confirmed against target vault contract. Immediate circuit-breaker pause required.",
        }),
    )

    # Step 3: Bob submits threat report with 1 GEN stake
    direct_vm.sender = direct_bob
    direct_vm.value = 1 * 10**18
    rep_id = contract.report_threat(
        vault_address,
        "https://github.com/advisories/GHSA-xxxx-yyyy",
        "Critical reentrancy vulnerability detected in depositYield.",
    )
    assert rep_id == 0

    # Step 4: Verify vault is now PAUSED and bounty awarded
    v_after = contract.get_vault(vault_address)
    assert v_after["is_paused"] is True
    assert v_after["last_threat_level"] == "CRITICAL"
    assert v_after["total_reports"] == 1
    # 40 GEN pool - 10 GEN (25%) reward = 30 GEN remaining
    assert v_after["bounty_pool"] == str(30 * 10**18)

    rep = contract.get_threat_report(rep_id)
    assert rep["threat_level"] == "CRITICAL"
    assert rep["confidence_score"] == 96
    assert rep["adjudicated"] is True
    # Award = 10 GEN bounty + 1 GEN stake refund = 11 GEN
    assert rep["bounty_awarded"] == str(11 * 10**18)


def test_false_positive_stake_slashing(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Test that spam/false alarm reports result in stake slashing into the vault bounty pool without pausing the vault."""
    contract = direct_deploy("contracts/sentinai.py")
    vault_address = "0x2222222222222222222222222222222222222222"

    direct_vm.sender = direct_alice
    direct_vm.value = 20 * 10**18
    contract.register_vault(vault_address)

    # Mock web & LLM returning FALSE_POSITIVE
    direct_vm.mock_web(r".*", {"status": 200, "body": "Standard harmless transaction."})
    direct_vm.mock_llm(
        r".*",
        json.dumps({
            "threat_level": "FALSE_POSITIVE",
            "confidence_score": 15,
            "should_pause": False,
            "rationale": "No exploit signature or vulnerability detected. Normal user interaction.",
        }),
    )

    # Bob submits false report
    direct_vm.sender = direct_bob
    direct_vm.value = 1 * 10**18
    rep_id = contract.report_threat(
        vault_address,
        "https://example.com/normal-tx",
        "I think someone sent tokens.",
    )

    v = contract.get_vault(vault_address)
    assert v["is_paused"] is False  # Vault uptime preserved
    # 20 GEN initial + 1 GEN slashed stake = 21 GEN
    assert v["bounty_pool"] == str(21 * 10**18)

    rep = contract.get_threat_report(rep_id)
    assert rep["threat_level"] == "FALSE_POSITIVE"
    assert rep["bounty_awarded"] == "0"


def test_unauthorized_resume_protection(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Test that only the verified vault owner can resume a paused vault."""
    contract = direct_deploy("contracts/sentinai.py")
    vault_address = "0x3333333333333333333333333333333333333333"

    direct_vm.sender = direct_alice
    direct_vm.value = 10 * 10**18
    contract.register_vault(vault_address)

    # Manually pause via critical report
    direct_vm.mock_web(r".*", {"status": 200, "body": "exploit"})
    direct_vm.mock_llm(
        r".*",
        json.dumps({
            "threat_level": "CRITICAL",
            "confidence_score": 95,
            "should_pause": True,
            "rationale": "Critical exploit.",
        }),
    )
    direct_vm.sender = direct_bob
    direct_vm.value = 1 * 10**18
    contract.report_threat(vault_address, "https://exploit.com", "Exploit")

    # Bob tries to resume -> revert
    direct_vm.sender = direct_bob
    direct_vm.value = 0
    with direct_vm.expect_revert("Only the vault owner can resume a paused vault."):
        contract.resume_vault(vault_address)

    # Alice (Owner) resumes successfully
    direct_vm.sender = direct_alice
    contract.resume_vault(vault_address)

    v = contract.get_vault(vault_address)
    assert v["is_paused"] is False
    assert v["last_threat_level"] == "RESOLVED"
