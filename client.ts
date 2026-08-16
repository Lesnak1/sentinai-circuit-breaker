import { createClient, createAccount, type Address } from 'genlayer-js';
import { testnetBradbury } from 'genlayer-js/chains';

export const SENTINAI_ADDRESS: Address = '0x74e9242C875fcdd048E5BaB671902A29A5ddBA3c';

export function getGenLayerClient(privateKey?: `0x${string}`) {
  return createClient({
    chain: testnetBradbury,
    account: privateKey ? createAccount(privateKey) : createAccount(),
  });
}

/**
 * Registers a DeFi vault and funds the emergency whitehat bounty pool.
 */
export async function registerVault(
  client: ReturnType<typeof getGenLayerClient>,
  targetVault: Address,
  bountyDepositGen: number
) {
  const depositWei = BigInt(bountyDepositGen) * BigInt(10 ** 18);

  const txHash = await client.writeContract({
    address: SENTINAI_ADDRESS,
    functionName: 'register_vault',
    args: [targetVault],
    value: depositWei,
  });

  return txHash;
}

/**
 * Reports a critical exploit with live web advisory link (requires 1 GEN anti-spam stake).
 */
export async function reportThreat(
  client: ReturnType<typeof getGenLayerClient>,
  targetVault: Address,
  evidenceUrl: string,
  exploitSummary: string
) {
  const stakeWei = BigInt(1) * BigInt(10 ** 18); // 1 GEN stake

  const txHash = await client.writeContract({
    address: SENTINAI_ADDRESS,
    functionName: 'report_threat',
    args: [targetVault, evidenceUrl, exploitSummary],
    value: stakeWei,
  });

  return txHash;
}

/**
 * Queries vault protection status and bounty pool.
 */
export async function getVault(
  client: ReturnType<typeof getGenLayerClient>,
  targetVault: Address
) {
  return await client.readContract({
    address: SENTINAI_ADDRESS,
    functionName: 'get_vault',
    args: [targetVault],
  });
}
