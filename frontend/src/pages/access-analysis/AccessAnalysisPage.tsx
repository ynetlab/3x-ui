import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router';
import {
  Alert,
  Avatar,
  Button,
  Card,
  Collapse,
  ConfigProvider,
  DatePicker,
  Empty,
  Flex,
  Form,
  Layout,
  Pagination,
  Select,
  Skeleton,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
  Upload,
  message,
} from 'antd';
import {
  AppstoreOutlined,
  AppleFilled,
  GithubFilled,
  GoogleOutlined,
  ReloadOutlined,
  TwitterOutlined,
  UploadOutlined,
  YoutubeFilled,
} from '@ant-design/icons';
import dayjs from 'dayjs';
import type { Dayjs } from 'dayjs';
import AppSidebar from '@/layouts/AppSidebar';
import { useTheme } from '@/hooks/useTheme';
import { useAccessLogNodes, useAccessLogUsers } from '@/api/queries/useAccessLogs';
import { useAccessOverview, useAccessStats } from '@/api/queries/useAccessAnalysis';
import type { AnalysisItem, AnalysisQuery, Application } from '@/schemas/access-analysis';
import { HttpUtil } from '@/utils';
import UserLabel from '../access-logs/UserLabel';
import {
  ACCESS_LOG_TIME_FORMAT,
  availableTimeZones,
  filterTime,
  formatLogTime,
  systemTimeZone,
} from '../access-logs/timeZone';
import AnalysisNavigation from './AnalysisNavigation';
import { readSharedFilters, writeSharedFilters, validTimeZone } from './sharedFilters';
import '../access-logs/AccessLogsPage.css';
import './AccessAnalysisPage.css';

const SourceMap = lazy(() => import('./SourceMap'));
const brandIcons: Record<string, React.ReactNode> = {
  youtube: <YoutubeFilled aria-hidden />,
  github: <GithubFilled aria-hidden />,
  google: <GoogleOutlined aria-hidden />,
  apple: <AppleFilled aria-hidden />,
  twitter: <TwitterOutlined aria-hidden />,
};
const region = (row: AnalysisItem) => [row.country, row.subdivision].filter(Boolean).join(' · ');
type Filters = {
  nodeGuid?: string;
  user?: string;
  category?: AnalysisQuery['category'];
  timeRange?: [Dayjs | null, Dayjs | null];
};

function Attribution() {
  return (
    <Typography.Paragraph className="access-analysis-attribution" type="secondary">
      <a href="https://db-ip.com" target="_blank" rel="noreferrer">
        IP Geolocation by DB-IP
      </a>{' '}
      ·{' '}
      <a href="https://www.naturalearthdata.com" target="_blank" rel="noreferrer">
        Natural Earth
      </a>
    </Typography.Paragraph>
  );
}

function AppLabel({ id, catalog }: { id: string; catalog: Map<string, Application> }) {
  const { t } = useTranslation();
  const app = catalog.get(id);
  const name = app?.name ?? (id === 'unknown' ? t('accessAnalysis.unknownApp') : id);
  return (
    <span className="access-analysis-app-label">
      <Avatar
        shape="square"
        size={24}
        style={{ background: app?.color ?? '#64748b' }}
        icon={brandIcons[id] ?? <AppstoreOutlined aria-hidden />}
      />
      <span className="access-analysis-app-name" title={name}>
        {name}
      </span>
    </span>
  );
}

function StatsDetail({
  query,
  email,
  catalog,
  zone,
}: {
  query: AnalysisQuery;
  email: string;
  catalog: Map<string, Application>;
  zone: string;
}) {
  const { t } = useTranslation();
  const [kind, setKind] = useState<'apps' | 'domains' | 'sources' | 'blocked'>('apps');
  const [page, setPage] = useState(1);
  const excludedByCategory = kind === 'blocked' && !!query.category && query.category !== 'blocked';
  const stats = useAccessStats(
    {
      ...query,
      user: email,
      userSet: true,
      kind: kind === 'blocked' ? 'domains' : kind,
      category: kind === 'blocked' ? 'blocked' : query.category,
      page,
      pageSize: 10,
    },
    !excludedByCategory,
  );
  const pageCatalog = useMemo(
    () =>
      new Map([...catalog, ...(stats.data?.catalog ?? []).map((app) => [app.id, app] as const)]),
    [catalog, stats.data?.catalog],
  );
  return (
    <>
      <Tabs
        activeKey={kind}
        items={[
          { key: 'apps', label: t('accessAnalysis.apps') },
          { key: 'domains', label: t('accessAnalysis.domains') },
          { key: 'sources', label: t('accessAnalysis.sourceIPs') },
          { key: 'blocked', label: t('accessAnalysis.blockedDomains') },
        ]}
        onChange={(key) => {
          setKind(key as typeof kind);
          setPage(1);
        }}
      />
      {!excludedByCategory && stats.isError && (
        <Alert
          type="error"
          showIcon
          title={t('accessLogs.loadError')}
          action={<Button onClick={() => void stats.refetch()}>{t('refresh')}</Button>}
        />
      )}
      <Table<AnalysisItem>
        size="small"
        rowKey={(row) => `${row.name}:${row.country}:${row.subdivision}`}
        dataSource={excludedByCategory ? [] : (stats.data?.items ?? [])}
        loading={stats.isFetching}
        scroll={{ x: 460 }}
        pagination={{
          current: stats.data?.page ?? page,
          pageSize: 10,
          total: excludedByCategory ? 0 : (stats.data?.total ?? 0),
          showSizeChanger: false,
          onChange: setPage,
        }}
        columns={[
          {
            title: t(
              kind === 'apps'
                ? 'accessAnalysis.apps'
                : kind === 'domains'
                  ? 'accessAnalysis.domains'
                  : kind === 'blocked'
                    ? 'accessAnalysis.blockedDomains'
                    : 'accessAnalysis.sourceIPs',
            ),
            dataIndex: 'name',
            render: (value: string, row) =>
              kind === 'apps' ? (
                <AppLabel id={value} catalog={pageCatalog} />
              ) : (
                <>
                  <Typography.Text className="access-analysis-target">
                    {value || t('accessAnalysis.unknownIP')}
                  </Typography.Text>
                  {kind === 'sources' && (
                    <div className="access-analysis-secondary">
                      {region(row) || t('accessAnalysis.unknownRegion')}
                    </div>
                  )}
                </>
              ),
          },
          {
            title: t('accessAnalysis.count'),
            dataIndex: 'count',
            width: 110,
            align: 'right',
            render: (value: number) => value.toLocaleString(),
          },
          ...(kind === 'sources'
            ? [
                {
                  title: t('accessAnalysis.lastSeen'),
                  dataIndex: 'lastSeen',
                  render: (value: number) => formatLogTime(value, zone),
                },
              ]
            : []),
        ]}
      />
    </>
  );
}

function RankedList({
  rows,
  kind,
  comments,
}: {
  rows: AnalysisItem[];
  kind: 'domains' | 'users';
  comments: Map<string, string>;
}) {
  const { t } = useTranslation();
  if (!rows.length) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />;
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <ol className="access-analysis-ranking">
      {rows.map((row, index) => (
        <li key={row.name}>
          <div className="access-analysis-ranked-line">
            <span className="access-analysis-rank">{index + 1}</span>
            <div className="access-analysis-name">
              {kind === 'users' ? (
                row.name ? (
                  <UserLabel email={row.name} comment={comments.get(row.name)} />
                ) : (
                  t('accessAnalysis.unknownUser')
                )
              ) : (
                <Typography.Text title={row.name}>{row.name || '—'}</Typography.Text>
              )}
            </div>
            <strong>{row.count.toLocaleString()}</strong>
          </div>
          <div className="access-analysis-track">
            <div style={{ width: `${(row.count / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ol>
  );
}

export default function AccessAnalysisPage() {
  const { t } = useTranslation();
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const [search, setSearch] = useSearchParams();
  const queryClient = useQueryClient();
  const usersView = search.get('tab') === 'users';
  const selectedZone = validTimeZone(search.get('zone'));
  const localZone = systemTimeZone();
  const zone = selectedZone === 'system' ? localZone : selectedZone;
  const [form] = Form.useForm<Filters>();
  const query = useMemo<AnalysisQuery>(() => {
    const values = readSharedFilters(search);
    return search.has('from') || search.has('to')
      ? values
      : {
          ...values,
          from: dayjs().tz(zone).startOf('day').valueOf(),
          to: dayjs().tz(zone).endOf('day').valueOf(),
        };
  }, [search, zone]);
  useEffect(() => {
    form.setFieldsValue({
      ...query,
      timeRange: [
        query.from ? dayjs(query.from).tz(zone) : null,
        query.to ? dayjs(query.to).tz(zone) : null,
      ],
    });
  }, [query, zone, form]);
  const [page, setPage] = useState(1);
  const [activeUsers, setActiveUsers] = useState<string[]>([]);
  const [userOpen, setUserOpen] = useState(false);
  const [userSearch, setUserSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(userSearch), 250);
    return () => clearTimeout(timer);
  }, [userSearch]);
  const nodes = useAccessLogNodes();
  const users = useAccessLogUsers(debouncedSearch, userOpen);
  const overview = useAccessOverview(query);
  const userStats = useAccessStats({ ...query, kind: 'users', page, pageSize: 12 }, usersView);
  useEffect(() => {
    void queryClient.invalidateQueries({ queryKey: ['access-analysis', 'stats'] });
  }, [queryClient, overview.data?.status.generation, overview.data?.status.processedId]);
  const catalog = useMemo(
    () => new Map((overview.data?.catalog ?? []).map((app) => [app.id, app])),
    [overview.data?.catalog],
  );
  const comments = useMemo(
    () => new Map(Object.entries(overview.data?.userComments ?? {})),
    [overview.data?.userComments],
  );
  const userComments = useMemo(
    () => new Map(Object.entries(userStats.data?.userComments ?? {})),
    [userStats.data?.userComments],
  );
  const userOptions = useMemo(() => {
    const labels = new Map<string, string>();
    if (query.user) labels.set(query.user, comments.get(query.user) ?? '');
    for (const p of users.data?.pages ?? [])
      for (const user of p.items) labels.set(user.email, user.comment ?? '');
    return [...labels].map(([value, comment]) => ({ value, label: value, comment }));
  }, [users.data, query.user, comments]);
  const initialValues: Filters = {
    ...query,
    timeRange: [
      query.from ? dayjs(query.from).tz(zone) : null,
      query.to ? dayjs(query.to).tz(zone) : null,
    ],
  };

  function updateUrl(next: AnalysisQuery, nextZone = selectedZone) {
    setSearch(writeSharedFilters(search, next, nextZone), { replace: true });
  }
  function apply(values: Filters) {
    const next: AnalysisQuery = {
      nodeGuid: values.nodeGuid,
      user: values.user,
      category: values.category,
      from: filterTime(values.timeRange?.[0], zone),
      to: filterTime(values.timeRange?.[1], zone),
    };
    setPage(1);
    setActiveUsers([]);
    updateUrl(next);
    if (JSON.stringify(next) === JSON.stringify(query)) {
      void queryClient.invalidateQueries({ queryKey: ['access-analysis'] });
    }
  }
  function changeZone(value: string) {
    const next = value === 'system' ? localZone : value;
    const range = form.getFieldValue('timeRange') as Filters['timeRange'];
    if (range)
      form.setFieldValue(
        'timeRange',
        range.map((date) => {
          const timestamp = filterTime(date, zone);
          return timestamp === undefined ? date : dayjs(timestamp).tz(next);
        }),
      );
    updateUrl(query, value);
  }
  const zoneOptions = [
    { value: 'system', label: t('accessLogs.systemTimeZone', { zone: localZone }) },
    ...availableTimeZones(localZone).map((value) => ({ value, label: value })),
  ];
  const data = overview.data;
  return (
    <ConfigProvider theme={antdThemeConfig}>
      <Layout
        className={`access-logs-page access-analysis-page${isDark ? ' is-dark' : ''}${isUltra ? ' is-ultra' : ''}`}
      >
        <AppSidebar />
        <Layout className="content-shell">
          <Layout.Content id="content-layout" className="content-area">
            <Card
              title={t('accessAnalysis.title')}
              extra={
                <Space wrap>
                  <Upload
                    accept=".mmdb"
                    showUploadList={false}
                    beforeUpload={async (file) => {
                      const body = new FormData();
                      body.append('file', file);
                      try {
                        const response = await HttpUtil.post(
                          '/panel/api/access-analysis/mmdb',
                          body,
                          { silent: true },
                        );
                        if (!response.success) throw new Error();
                        void message.success(t('accessAnalysis.imported'));
                        void overview.refetch();
                      } catch {
                        void message.error(t('accessAnalysis.importFailed'));
                      }
                      return false;
                    }}
                  >
                    <Button icon={<UploadOutlined aria-hidden />}>
                      {t('accessAnalysis.importMMDB')}
                    </Button>
                  </Upload>
                  <Button
                    icon={<ReloadOutlined aria-hidden />}
                    loading={overview.isFetching || userStats.isFetching}
                    onClick={() => {
                      void queryClient.invalidateQueries({ queryKey: ['access-analysis'] });
                    }}
                  >
                    {t('refresh')}
                  </Button>
                </Space>
              }
            >
              <AnalysisNavigation query={query} zone={selectedZone} />
              <Form form={form} layout="vertical" initialValues={initialValues} onFinish={apply}>
                <div className="access-analysis-filters">
                  <Form.Item label={t('accessLogs.node')} name="nodeGuid">
                    <Select
                      allowClear
                      showSearch={{ optionFilterProp: 'label' }}
                      placeholder={t('all')}
                      loading={nodes.isFetching}
                      options={(nodes.data ?? []).map((node) => ({
                        value: node.guid,
                        label: node.local ? t('accessLogs.localNode') : node.name || node.guid,
                      }))}
                    />
                  </Form.Item>
                  <Form.Item label={t('accessLogs.user')} name="user">
                    <Select
                      className="access-log-user-select"
                      classNames={{ popup: { root: 'access-log-user-popup' } }}
                      allowClear
                      showSearch={{ filterOption: false, onSearch: setUserSearch }}
                      options={userOptions}
                      loading={users.isFetching}
                      onOpenChange={setUserOpen}
                      placeholder={t('all')}
                      optionRender={(option) => (
                        <UserLabel email={option.data.value} comment={option.data.comment} />
                      )}
                      labelRender={({ value }) => (
                        <UserLabel
                          email={String(value)}
                          comment={userOptions.find((user) => user.value === value)?.comment}
                        />
                      )}
                      onPopupScroll={(event) => {
                        const el = event.currentTarget;
                        if (
                          el.scrollTop + el.clientHeight >= el.scrollHeight - 32 &&
                          users.hasNextPage &&
                          !users.isFetchingNextPage
                        )
                          void users.fetchNextPage();
                      }}
                    />
                  </Form.Item>
                  <Form.Item label={t('accessLogs.timeZone')} htmlFor="analysis-time-zone">
                    <Select
                      id="analysis-time-zone"
                      value={selectedZone}
                      options={zoneOptions}
                      showSearch={{ optionFilterProp: 'label' }}
                      onChange={changeZone}
                    />
                  </Form.Item>
                  <Form.Item
                    name="timeRange"
                    label={t('accessLogs.timeRange')}
                    className="access-log-time-range"
                    rules={[
                      {
                        validator: (_, range: Filters['timeRange']) => {
                          const from = filterTime(range?.[0], zone),
                            to = filterTime(range?.[1], zone);
                          if (
                            (range?.[0] && from === undefined) ||
                            (range?.[1] && to === undefined)
                          )
                            return Promise.reject(new Error(t('accessLogs.invalidLocalTime')));
                          return from === undefined || to === undefined || from <= to
                            ? Promise.resolve()
                            : Promise.reject(new Error(t('accessLogs.invalidTimeRange')));
                        },
                      },
                    ]}
                  >
                    <DatePicker.RangePicker
                      showTime
                      allowEmpty={[true, true]}
                      format={ACCESS_LOG_TIME_FORMAT}
                      presets={[
                        {
                          label: t('accessAnalysis.today'),
                          value: [dayjs().tz(zone).startOf('day'), dayjs().tz(zone).endOf('day')],
                        },
                        {
                          label: t('accessAnalysis.last7Days'),
                          value: [dayjs().tz(zone).subtract(7, 'day'), dayjs().tz(zone)],
                        },
                        {
                          label: t('accessAnalysis.last30Days'),
                          value: [dayjs().tz(zone).subtract(30, 'day'), dayjs().tz(zone)],
                        },
                      ]}
                    />
                  </Form.Item>
                  <div className="access-analysis-filter-actions">
                    <Form.Item name="category" label={t('accessLogs.category')}>
                      <Select
                        allowClear
                        placeholder={t('all')}
                        options={(['direct', 'blocked', 'proxy'] as const).map((value) => ({
                          value,
                          label: t(`accessLogs.${value}`),
                        }))}
                      />
                    </Form.Item>
                    <Form.Item>
                      <Button type="primary" htmlType="submit">
                        {t('search')}
                      </Button>
                    </Form.Item>
                  </div>
                </div>
              </Form>
              {(overview.isError || nodes.isError || users.isError) && (
                <Alert showIcon type="error" title={t('accessLogs.loadError')} />
              )}
              {data &&
                (!data.status.ready ||
                  data.status.rebuilding ||
                  data.status.processedId < data.status.latestId) && (
                  <Alert
                    showIcon
                    type="info"
                    title={t('accessAnalysis.processing')}
                    description={t('accessAnalysis.processingHint')}
                  />
                )}
              {data && !data.status.locationReady && (
                <Alert showIcon type="warning" title={t('accessAnalysis.locationPending')} />
              )}
            </Card>
            {usersView ? (
              <Card title={t('accessAnalysis.periodUsers')} className="access-analysis-section">
                {userStats.isError && (
                  <Alert type="error" showIcon title={t('accessLogs.loadError')} />
                )}
                {userStats.isPending ? (
                  <Skeleton active />
                ) : !userStats.data?.items.length ? (
                  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : (
                  <Collapse
                    className="access-analysis-user-cards"
                    activeKey={activeUsers}
                    onChange={(keys) => setActiveUsers(Array.isArray(keys) ? keys : [keys])}
                    items={userStats.data.items.map((row) => ({
                      key: row.name,
                      label: (
                        <Flex justify="space-between" align="center" gap={16}>
                          <div>
                            {row.name ? (
                              <UserLabel email={row.name} comment={userComments.get(row.name)} />
                            ) : (
                              t('accessAnalysis.unknownUser')
                            )}
                          </div>
                          <Tag color="blue">{t('accessAnalysis.events', { count: row.count })}</Tag>
                        </Flex>
                      ),
                      children: activeUsers.includes(row.name) ? (
                        <StatsDetail
                          key={`${row.name}:${JSON.stringify(query)}`}
                          query={query}
                          email={row.name}
                          catalog={catalog}
                          zone={zone}
                        />
                      ) : null,
                    }))}
                  />
                )}
                <Pagination
                  className="access-analysis-pagination"
                  current={userStats.data?.page ?? page}
                  pageSize={12}
                  total={userStats.data?.total ?? 0}
                  showSizeChanger={false}
                  onChange={(value) => {
                    setPage(value);
                    setActiveUsers([]);
                  }}
                />
                <Attribution />
              </Card>
            ) : (
              <>
                <div className="access-analysis-geography access-analysis-section">
                  <Card
                    title={t('accessAnalysis.sourceMap')}
                    extra={<Tag>{t('accessAnalysis.events', { count: data?.total ?? 0 })}</Tag>}
                  >
                    <Suspense fallback={<Skeleton active />}>
                      <SourceMap rows={data?.regions ?? []} dark={isDark} />
                    </Suspense>
                    <Attribution />
                  </Card>
                  <Card title={t('accessAnalysis.recentIPs')}>
                    <Table<AnalysisItem>
                      size="small"
                      rowKey={(row) => `${row.name}:${row.subdivision}`}
                      dataSource={data?.sources ?? []}
                      scroll={{ y: 348 }}
                      loading={overview.isPending}
                      pagination={false}
                      columns={[
                        {
                          title: t('accessLogs.source'),
                          dataIndex: 'name',
                          render: (value: string, row) => (
                            <>
                              <Typography.Text className="access-analysis-target">
                                {value || t('accessAnalysis.unknownIP')}
                              </Typography.Text>
                              <div className="access-analysis-secondary">
                                {region(row) || t('accessAnalysis.unknownRegion')}
                              </div>
                              <div className="access-analysis-secondary">
                                {formatLogTime(row.lastSeen, zone)}
                              </div>
                            </>
                          ),
                        },
                        {
                          title: t('accessAnalysis.count'),
                          dataIndex: 'count',
                          align: 'right',
                          render: (value: number) => value.toLocaleString(),
                        },
                      ]}
                    />
                  </Card>
                </div>
                <Card title={t('accessAnalysis.topApps')} className="access-analysis-section">
                  {overview.isPending ? (
                    <Skeleton active />
                  ) : !data?.apps.length ? (
                    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                  ) : (
                    <div className="access-analysis-app-grid">
                      {data.apps.map((row) => (
                        <div className="access-analysis-app" key={row.name}>
                          <AppLabel id={row.name} catalog={catalog} />
                          <div className="access-analysis-app-meter">
                            <div className="access-analysis-track">
                              <div
                                style={{
                                  width: `${(row.count / Math.max(1, data.apps[0]?.count ?? 1)) * 100}%`,
                                }}
                              />
                            </div>
                            <strong>{row.count.toLocaleString()}</strong>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Card>
                <div className="access-analysis-bottom access-analysis-section">
                  <Card title={t('accessAnalysis.topDomains')}>
                    <RankedList rows={data?.domains ?? []} kind="domains" comments={comments} />
                  </Card>
                  <Card title={t('accessAnalysis.recentBlocked')}>
                    {!data?.blocked.length ? (
                      <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                    ) : (
                      <ul className="access-analysis-blocked">
                        {data.blocked.map((row) => (
                          <li key={row.id}>
                            <Typography.Text className="access-analysis-target">
                              {row.target}
                            </Typography.Text>
                            <div className="access-analysis-secondary">
                              {formatLogTime(row.occurredAt, zone)} · {row.outbound || '—'}
                            </div>
                            <Tag color="red">{t('accessLogs.blocked')}</Tag>
                          </li>
                        ))}
                      </ul>
                    )}
                  </Card>
                  <Card title={t('accessAnalysis.topUsers')}>
                    <RankedList rows={data?.users ?? []} kind="users" comments={comments} />
                  </Card>
                </div>
              </>
            )}
          </Layout.Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
