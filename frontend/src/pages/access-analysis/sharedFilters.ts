import type { AnalysisQuery } from '@/schemas/access-analysis';

export function validTimeZone(value: string | null): string {
  if (!value || value === 'system') return 'system';
  try {
    new Intl.DateTimeFormat('en', { timeZone: value });
    return value;
  } catch {
    return 'system';
  }
}

export function readSharedFilters(search: URLSearchParams): AnalysisQuery {
  const timestamp = (key: string) => {
    const value = Number(search.get(key));
    return Number.isSafeInteger(value) && value > 0 && value <= 253402300799999 ? value : undefined;
  };
  const category = search.get('category');
  return {
    from: timestamp('from'),
    to: timestamp('to'),
    nodeGuid: search.get('nodeGuid') || undefined,
    user: search.get('user') || undefined,
    category:
      category === 'blocked' || category === 'direct' || category === 'proxy'
        ? category
        : undefined,
  };
}

export function writeSharedFilters(
  search: URLSearchParams,
  query: AnalysisQuery,
  zone: string,
): URLSearchParams {
  const params = new URLSearchParams(search);
  for (const key of ['from', 'to', 'nodeGuid', 'user', 'category'] as const) {
    const value = query[key];
    if (value === undefined || value === '') params.delete(key);
    else params.set(key, String(value));
  }
  params.set('zone', zone);
  if (query.from === undefined && query.to === undefined) {
    params.set('from', '0');
    params.set('to', '0');
  }
  return params;
}
