# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
SentinAI: Autonomous AI Security Circuit Breaker & Real-Time Threat Oracle on GenLayer.

A reusable security primitive allowing Web3 protocols and vaults to register emergency
circuit-breaker protections. Threat advisories are independently verified by GenLayer
validators via live web intelligence (CertiK, PeckShield, GitHub Security Advisories).
When a critical exploit is verified, SentinAI deterministically pauses the target protocol
and distributes a bounty to the whitehat reporter.
"""

from genlayer import *
from dataclasses import dataclass
import json


@allow_storage
@dataclass
class ProtectedVault:
    vault_address: Address
    owner: Address
    bounty_pool: u256
    is_paused: bool
    last_threat_level: str
    total_reports: u32


@allow_storage
@dataclass
class ThreatReport:
    vault_address: Address
    reporter: Address
    evidence_url: str
    threat_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "FALSE_POSITIVE"
    confidence_score: u32  # 0 - 100
    adjudicated: bool
    bounty_awarded: u256
    summary: str


# EVM / IC interface for triggering emergency pause on protected vaults
@gl.evm.contract_interface
class IPausableVault:
    class View:
        pass

    class Write:
        def pause(self) -> None: ...
        def unpause(self) -> None: ...


class SentinAI(gl.Contract):
    """Autonomous Threat Oracle and Security Circuit Breaker for GenLayer."""

    vaults: TreeMap[Address, ProtectedVault]
    reports: TreeMap[u256, ThreatReport]
    report_counter: u256
    min_report_stake: u256

    def __init__(self):
        self.report_counter = u256(0)
        self.min_report_stake = u256(1 * 10**18)  # 1 GEN anti-spam stake

    @gl.public.write.payable
    def register_vault(self, target_vault: str) -> None:
        """Protocol owner registers their vault and deposits initial GEN into the emergency bounty pool."""
        deposit_val = gl.message.value
        vault_addr = Address(target_vault)

        existing = self.vaults.get(vault_addr, None)
        if existing is not None:
            # Top up existing bounty pool
            existing.bounty_pool = existing.bounty_pool + deposit_val
            self.vaults[vault_addr] = existing
            return

        self.vaults[vault_addr] = ProtectedVault(
            vault_address=vault_addr,
            owner=gl.message.sender_address,
            bounty_pool=deposit_val,
            is_paused=False,
            last_threat_level="NONE",
            total_reports=u32(0),
        )

    @gl.public.write.payable
    def report_threat(
        self, target_vault: str, evidence_url: str, exploit_summary: str
    ) -> u256:
        """
        Security researcher submits an urgent threat report with live web evidence.
        Requires 1 GEN anti-spam stake. Triggers multi-validator neural consensus.
        """
        stake = gl.message.value
        if stake < self.min_report_stake:
            raise gl.vm.UserError("Submitting a threat report requires at least 1 GEN anti-spam stake.")

        vault_addr = Address(target_vault)
        vault = self.vaults.get(vault_addr, None)
        if vault is None:
            raise gl.vm.UserError("Target vault is not registered with SentinAI protection.")

        if vault.is_paused:
            raise gl.vm.UserError("Vault is already in an emergency paused state.")

        report_id = self.report_counter
        self.report_counter = self.report_counter + u256(1)

        reporter_addr = gl.message.sender_address
        target_str = str(vault_addr)

        # Leader validator fetches real-time web intelligence and parses threat
        def leader_fn() -> dict:
            evidence_text = ""
            if evidence_url and evidence_url.startswith("http"):
                try:
                    res = gl.nondet.web.get(evidence_url)
                    if hasattr(res, "body"):
                        evidence_text = res.body.decode("utf-8", errors="replace")[:3000]
                    else:
                        evidence_text = str(res)[:3000]
                except Exception:
                    evidence_text = "Live advisory fetch error or timeout."

            prompt = f"""
            You are the SentinAI Web3 Threat Oracle.
            Analyze the submitted vulnerability/exploit evidence for target contract: {target_str}.

            === RESEARCHER SUMMARY ===
            {exploit_summary}

            === LIVE WEB EVIDENCE (EXTRACTED FROM {evidence_url}) ===
            {evidence_text}

            Determine:
            1. "threat_level": Must be one of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "FALSE_POSITIVE"].
               - "CRITICAL": Active exploit, drain in progress, or verified private key/logic compromise.
               - "HIGH": Severe unexploited vulnerability with valid PoC.
               - "MEDIUM" / "LOW": Minor griefing or theoretical non-loss issues.
               - "FALSE_POSITIVE": Irrelevant, spam, or invalid evidence.
            2. "confidence_score": Integer 0 to 100 representing certainty.
            3. "should_pause": Boolean true ONLY if threat_level in ["CRITICAL", "HIGH"] and confidence_score >= 80.
            4. "rationale": 1-2 sentence technical assessment.

            Respond ONLY with a valid JSON object matching this schema:
            {{
                "threat_level": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"FALSE_POSITIVE",
                "confidence_score": int,
                "should_pause": bool,
                "rationale": "string"
            }}
            """
            analysis = gl.nondet.exec_prompt(prompt, response_format="json")
            if not isinstance(analysis, dict):
                raise gl.vm.UserError("Oracle LLM must return a valid JSON object.")
            return analysis

        # Validators independently evaluate threat intelligence under the Equivalence Principle
        def validator_fn(leaders_res: gl.vm.Result) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return False

            lead = leaders_res.calldata
            if not isinstance(lead, dict):
                return False

            for k in ["threat_level", "confidence_score", "should_pause", "rationale"]:
                if k not in lead:
                    return False

            val = leader_fn()

            # Threat level classification must match exactly
            if lead.get("threat_level") != val.get("threat_level"):
                return False

            # Emergency action verdict must agree
            if bool(lead.get("should_pause")) != bool(val.get("should_pause")):
                return False

            # Confidence score tolerance within ±6 points
            l_conf = int(lead.get("confidence_score", 0))
            v_conf = int(val.get("confidence_score", 0))
            if abs(l_conf - v_conf) > 6:
                return False

            return True

        # Run multi-validator consensus
        verdict = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

        level = str(verdict.get("threat_level", "FALSE_POSITIVE"))
        conf = u32(int(verdict.get("confidence_score", 0)))
        should_pause = bool(verdict.get("should_pause", False))
        rationale = str(verdict.get("rationale", ""))

        bounty_payout = u256(0)

        # Deterministic Financial & Circuit-Breaker Gate
        if should_pause and (level == "CRITICAL" or level == "HIGH") and conf >= u32(80):
            vault.is_paused = True
            vault.last_threat_level = level

            # Calculate bounty reward: 25% of available bounty pool + full stake refund
            pool = vault.bounty_pool
            if pool > u256(0):
                reward_portion = pool // u256(4)
                vault.bounty_pool = pool - reward_portion
                bounty_payout = reward_portion + stake
            else:
                bounty_payout = stake

            # 1. Trigger Circuit Breaker: Emergency Pause target vault on finality
            IPausableVault(vault_addr).emit().pause()

            # 2. Distribute whitehat bounty + stake refund
            @gl.evm.contract_interface
            class _Recipient:
                class View:
                    pass
                class Write:
                    pass

            _Recipient(reporter_addr).emit_transfer(value=bounty_payout)

        elif level == "FALSE_POSITIVE":
            # Slash anti-spam stake into vault's bounty pool to deter spam
            vault.bounty_pool = vault.bounty_pool + stake
            bounty_payout = u256(0)
        else:
            # Non-critical but valid: refund stake
            @gl.evm.contract_interface
            class _Recipient:
                class View:
                    pass
                class Write:
                    pass

            _Recipient(reporter_addr).emit_transfer(value=stake)

        vault.total_reports = vault.total_reports + u32(1)
        self.vaults[vault_addr] = vault

        self.reports[report_id] = ThreatReport(
            vault_address=vault_addr,
            reporter=reporter_addr,
            evidence_url=evidence_url,
            threat_level=level,
            confidence_score=conf,
            adjudicated=True,
            bounty_awarded=bounty_payout,
            summary=rationale,
        )

        return report_id

    @gl.public.write
    def resume_vault(self, target_vault: str) -> None:
        """Only the vault owner can resume/unpause the vault after security patch verification."""
        vault_addr = Address(target_vault)
        vault = self.vaults.get(vault_addr, None)
        if vault is None:
            raise gl.vm.UserError("Vault not registered.")

        if gl.message.sender_address != vault.owner:
            raise gl.vm.UserError("Only the vault owner can resume a paused vault.")

        if not vault.is_paused:
            raise gl.vm.UserError("Vault is not currently paused.")

        vault.is_paused = False
        vault.last_threat_level = "RESOLVED"
        self.vaults[vault_addr] = vault

        IPausableVault(vault_addr).emit().unpause()

    @gl.public.view
    def get_vault(self, target_vault: str) -> dict:
        """View protection state and bounty pool of a vault."""
        vault_addr = Address(target_vault)
        v = self.vaults.get(vault_addr, None)
        if v is None:
            raise gl.vm.UserError("Vault not found.")
        return {
            "vault_address": str(v.vault_address),
            "owner": str(v.owner),
            "bounty_pool": str(v.bounty_pool),
            "is_paused": v.is_paused,
            "last_threat_level": v.last_threat_level,
            "total_reports": int(v.total_reports),
        }

    @gl.public.view
    def get_threat_report(self, report_id: u256) -> dict:
        """View full adjudication details for a threat report."""
        rep = self.reports.get(report_id, None)
        if rep is None:
            raise gl.vm.UserError("Report not found.")
        return {
            "vault_address": str(rep.vault_address),
            "reporter": str(rep.reporter),
            "evidence_url": rep.evidence_url,
            "threat_level": rep.threat_level,
            "confidence_score": int(rep.confidence_score),
            "adjudicated": rep.adjudicated,
            "bounty_awarded": str(rep.bounty_awarded),
            "summary": rep.summary,
        }
