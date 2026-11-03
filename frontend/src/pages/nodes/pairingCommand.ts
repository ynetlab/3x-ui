import { Base64 } from '@/utils';

export interface PairingPeer {
  guid: string;
  role: 'master' | 'slave';
  fingerprint: string;
}

export interface PairingControlInfo {
  enabled: boolean;
  port: number;
  peer: PairingPeer;
}

export interface PairingProfile {
  enrollmentId: string;
  masterAddress: string;
  masterPort: number;
  master: PairingPeer;
  token: string;
  expiresAt: number;
  recovery?: boolean;
  slaveGuid?: string;
}

export interface PairingStatus {
  id: string;
  status: string;
  expiresAt: number;
  resumeUntil?: number;
  lastError?: string;
  nodeId?: number;
  existingNodeId?: number;
  primaryDomain?: string;
  certificateStatus?: string;
}

export interface PairingJoinRequest {
  profile: PairingProfile;
  address: string;
  port: number;
  allowPrivateMaster: boolean;
}

export const pairingTerminal = (status: string) =>
  ['completed', 'expired', 'failed'].includes(status);

const quoteShell = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";

export function buildPairingCommand(binary: string, request: PairingJoinRequest): string {
  const path = binary.trim();
  if (!path.startsWith('/') || /[\r\n\0]/.test(path)) throw new Error('invalid_binary_path');
  const quotedPath = quoteShell(path);
  return `printf '%s' '${Base64.encode(JSON.stringify(request))}' | ${quotedPath} pairing ${request.profile.recovery ? 'recover' : 'join'} --stdin-base64`;
}

export function buildSlaveInstallCommand(release: string, request: PairingJoinRequest): string {
  const tag = release.trim();
  if (!/^(?:latest|dev|dev-latest|v?\d+\.\d+\.\d+(?:[-+.][A-Za-z0-9.-]+)?)$/.test(tag)) {
    throw new Error('invalid_install_release');
  }
  const script = [
    'set -e',
    'installer=$(mktemp)',
    'trap \'rm -f "$installer"\' EXIT',
    "curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15 -o \"$installer\" 'https://raw.githubusercontent.com/ynetlab/3x-ui/main/install.sh'",
    `XUI_SLAVE_INSTALL=1 XUI_NONINTERACTIVE=1 bash "$installer" ${quoteShell(tag)}`,
  ].join('; ');
  return `printf '%s' '${Base64.encode(JSON.stringify(request))}' | bash -c ${quoteShell(script)}`;
}
