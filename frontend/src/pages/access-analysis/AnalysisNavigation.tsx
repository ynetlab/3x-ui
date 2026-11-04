import { Tabs } from 'antd';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate } from 'react-router';
import type { AnalysisQuery } from '@/schemas/access-analysis';
import { writeSharedFilters } from './sharedFilters';

export default function AnalysisNavigation({
  query,
  zone,
}: { query?: AnalysisQuery; zone?: string } = {}) {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const params = query
    ? writeSharedFilters(new URLSearchParams(location.search), query, zone ?? 'system')
    : new URLSearchParams(location.search);
  const active =
    location.pathname === '/access-logs'
      ? 'details'
      : params.get('tab') === 'users'
        ? 'users'
        : 'overview';
  return (
    <Tabs
      activeKey={active}
      items={[
        { key: 'overview', label: t('accessAnalysis.overview') },
        { key: 'details', label: t('accessAnalysis.details') },
        { key: 'users', label: t('accessAnalysis.users') },
      ]}
      onChange={(key) => {
        if (key === 'users') params.set('tab', 'users');
        else params.delete('tab');
        void navigate({
          pathname: key === 'details' ? '/access-logs' : '/access-analysis',
          search: params.toString(),
        });
      }}
    />
  );
}
