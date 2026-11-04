import dayjs from 'dayjs';
import type { Dayjs } from 'dayjs';
import utc from 'dayjs/plugin/utc';
import timezone from 'dayjs/plugin/timezone';

dayjs.extend(utc);
dayjs.extend(timezone);

export const ACCESS_LOG_TIME_FORMAT = 'YYYY-MM-DD HH:mm:ss';

export function systemTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
}

export function availableTimeZones(localZone: string): string[] {
  const intl = Intl as typeof Intl & {
    supportedValuesOf?: (key: 'timeZone') => string[];
  };
  const zones = intl.supportedValuesOf?.('timeZone') ?? [
    'Asia/Shanghai',
    'Asia/Tokyo',
    'Asia/Singapore',
    'Asia/Dubai',
    'Europe/London',
    'Europe/Berlin',
    'America/New_York',
    'America/Los_Angeles',
    'Australia/Sydney',
  ];
  return [...new Set(['UTC', localZone, ...zones])].sort();
}

export function formatLogTime(timestamp: number, zone: string): string {
  return dayjs(timestamp).tz(zone).format(ACCESS_LOG_TIME_FORMAT);
}

export function filterTime(value: Dayjs | null | undefined, zone: string): number | undefined {
  if (!value?.isValid()) return undefined;
  const wallTime = value.format(ACCESS_LOG_TIME_FORMAT);
  // Preserve an existing instant, including the repeated hour when DST ends.
  if (formatLogTime(value.valueOf(), zone) === wallTime) {
    return value.millisecond(0).valueOf();
  }
  const parsed = dayjs.tz(wallTime, zone);
  // Reject nonexistent local times instead of silently moving the filter.
  return parsed.format(ACCESS_LOG_TIME_FORMAT) === wallTime ? parsed.valueOf() : undefined;
}
