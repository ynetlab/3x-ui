import { z } from 'zod';
import type { NodeDNSRecord } from '@/schemas/node-dns';

export function nodeDNSIP(value: string, type: string): boolean {
  return (type === 'A' ? z.ipv4() : z.ipv6()).safeParse(value).success;
}

export function nodeDNSName(value: string, zone: string): string | null {
  const raw = value.trim();
  if (raw === '@') return zone;
  const wildcard = raw.startsWith('*.') ? '*.' : '';
  const domain = raw.slice(wildcard.length).replace(/\.$/, '');
  if (!domain || /[\s/:\\?#@%]/u.test(domain)) return null;
  try {
    const name = `${wildcard}${new URL(`http://${domain}`).hostname.toLowerCase()}`;
    if (
      name.length > 253 ||
      name
        .slice(wildcard.length)
        .split('.')
        .some((part) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))
    )
      return null;
    return name === zone || name.endsWith(`.${zone}`) ? name : null;
  } catch {
    return null;
  }
}

export function nodeDNSSelectable(record: NodeDNSRecord): boolean {
  return (
    record.bound &&
    !record.missing &&
    !record.changed &&
    (record.type === 'A' || record.type === 'AAAA')
  );
}

export function nodeDNSCertificateDomains(records: NodeDNSRecord[]): string[] {
  return [
    ...new Set(records.filter(nodeDNSSelectable).map((record) => record.name.toLowerCase())),
  ].sort();
}
