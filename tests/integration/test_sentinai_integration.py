"""
Integration tests for SentinAI against GenLayer RPC / StudioNet / LocalNet.
"""

import pytest
from gltest import get_contract_factory
from gltest.assertions import tx_execution_succeeded


def test_sentinai_deployment_and_schema():
    """Validates contract deployment and schema generation on GenVM."""
    factory = get_contract_factory("contracts/sentinai.py")
    
    contract = factory.deploy(args=[])
    assert contract.address is not None
    assert contract.address.startswith("0x")

    # Querying unregistered vault should revert with clean UserError
    dummy_vault = "0x000000000000000000000000000000000000dEaD"
    with pytest.raises(Exception):
        contract.get_vault(args=[dummy_vault]).call()
