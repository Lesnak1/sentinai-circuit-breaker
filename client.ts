import { createClient, createAccount, generatePrivateKey, type Address } from 'genlayer-js';
import { testnetBradbury, studionet, localnet } from 'genlayer-js/chains';

/**
 * SentinAI GenLayer Client Integration
 * Provides complete TypeScript bindings for all security oracle methods:
 * - register_vault (Payable, registers vault and funds bounty reserve)
 * - report_threat (Payable, submits threat advisory with 1 GEN anti-spam stake)
 * - resume_vault (Owner unpauses vault after security patch)
 * - get_vault (Read-only view of protection state and bounty pool)
 * - get_threat_report (Read-only view of consensus adjudication and confidence scores)
 */

export const DEFAULT_SENTINAI_ADDRESS: Address = '0x74e9242C875fcdd048E5BaB671902A29A5ddBA3c';

export interface VaultState {
  vault_address: string;
  owner: string;
  bounty_pool: string;
  is_paused: boolean;
  last_threat_level: string;
  total_reports: number;
}

export interface ThreatReportState {
  vault_address: string;
  reporter: string;
  evidence_url: string;
  threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'FALSE_POSITIVE';
  confidence_score: number;
  action_decision: 'EMERGENCY_PAUSE' | 'DISMISS_SPAM' | 'INCONCLUSIVE_REFUND';
  adjudicated: boolean;
  bounty_awarded: string;
  summary: string;
}

export type SupportedChain = 'testnetBradbury' | 'studionet' | 'localnet';

export function getChainConfig(chainType: SupportedChain = 'testnetBradbury') {
  switch (chainType) {
    case 'studionet':
      return studionet;
    case 'localnet':
      return localnet;
    case 'testnetBradbury':
    default:
      return testnetBradbury;
  }
}

export function getGenLayerClient(
  privateKey?: `0x${string}`,
  chainType: SupportedChain = 'testnetBradbury'
) {
  const account = privateKey ? createAccount(privateKey) : createAccount(generatePrivateKey());
  const chain = getChainConfig(chainType);

  return createClient({
    chain,
    account,
  });
}

/**
 * Registers a DeFi vault and funds the emergency whitehat bounty pool.
 */
export async function registerVault(
  client: ReturnType<typeof getGenLayerClient>,
  contractAddress: Address,
  targetVault: Address,
  bountyDepositGen: string | number
): Promise<`0x${string}`> {
  const depositWei = BigInt(Math.floor(Number(bountyDepositGen) * 1e18));

  const txHash = await client.writeContract({
    address: contractAddress,
    functionName: 'register_vault',
    args: [targetVault],
    value: depositWei,
  });

  return txHash as `0x${string}`;
}

/**
 * Reports a critical exploit with live web advisory link (requires 1 GEN anti-spam stake).
 */
export async function reportThreat(
  client: ReturnType<typeof getGenLayerClient>,
  contractAddress: Address,
  targetVault: Address,
  evidenceUrl: string,
  exploitSummary: string
): Promise<`0x${string}`> {
  const stakeWei = BigInt(1 * 10 ** 18); // 1 GEN stake

  const txHash = await client.writeContract({
    address: contractAddress,
    functionName: 'report_threat',
    args: [targetVault, evidenceUrl, exploitSummary],
    value: stakeWei,
  });

  return txHash as `0x${string}`;
}

/**
 * Vault owner unpauses vault after verifying security patch.
 */
export async function resumeVault(
  client: ReturnType<typeof getGenLayerClient>,
  contractAddress: Address,
  targetVault: Address
): Promise<`0x${string}`> {
  const txHash = await client.writeContract({
    address: contractAddress,
    functionName: 'resume_vault',
    args: [targetVault],
  });

  return txHash as `0x${string}`;
}

/**
 * Queries vault protection status and bounty pool.
 */
export async function getVault(
  client: ReturnType<typeof getGenLayerClient>,
  contractAddress: Address,
  targetVault: Address
): Promise<VaultState> {
  const data = await client.readContract({
    address: contractAddress,
    functionName: 'get_vault',
    args: [targetVault],
  });

  return data as unknown as VaultState;
}

/**
 * Queries threat report status and consensus adjudication rationale.
 */
export async function getThreatReport(
  client: ReturnType<typeof getGenLayerClient>,
  contractAddress: Address,
  reportId: bigint | number
): Promise<ThreatReportState> {
  const data = await client.readContract({
    address: contractAddress,
    functionName: 'get_threat_report',
    args: [BigInt(reportId)],
  });

  return data as unknown as ThreatReportState;
}

/**
 * Waits for transaction finality and consensus receipt on GenLayer.
 */
export async function waitForTransactionReceipt(
  client: ReturnType<typeof getGenLayerClient>,
  hash: `0x${string}`
) {
  return await client.waitForTransactionReceipt({ hash });
}
