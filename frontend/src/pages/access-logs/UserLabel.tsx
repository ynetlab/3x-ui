import { Tooltip } from 'antd';

export function compactEmail(email: string): string {
  const characters = Array.from(email);
  if (characters.length <= 26) return email;
  const domain = email.lastIndexOf('@');
  const suffixLength = domain > 0 ? Math.min(Array.from(email.slice(domain)).length, 14) : 12;
  return `${characters.slice(0, 25 - suffixLength).join('')}…${characters.slice(-suffixLength).join('')}`;
}

export default function UserLabel({ email, comment }: { email: string; comment?: string }) {
  return (
    <span className="access-log-user">
      <Tooltip title={email}>
        <span className="access-log-user-email" aria-label={email}>
          {compactEmail(email) || '—'}
        </span>
      </Tooltip>
      {comment && <span className="access-log-user-comment">({comment})</span>}
    </span>
  );
}
