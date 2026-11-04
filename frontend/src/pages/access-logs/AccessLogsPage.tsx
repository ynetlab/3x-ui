import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import AnalysisNavigation from '../access-analysis/AnalysisNavigation';
import {
  readSharedFilters,
  writeSharedFilters,
  validTimeZone,
} from '../access-analysis/sharedFilters';
import { useTranslation } from 'react-i18next';
import {
  Button,
  Card,
  ConfigProvider,
  DatePicker,
  Form,
  Input,
  Layout,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Alert,
} from 'antd';
import type { TableColumnsType } from 'antd';
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import dayjs from 'dayjs';
import type { Dayjs } from 'dayjs';

import AppSidebar from '@/layouts/AppSidebar';
import { useTheme } from '@/hooks/useTheme';
import { useAccessLogNodes, useAccessLogs, useAccessLogUsers } from '@/api/queries/useAccessLogs';
import type { AccessLogQuery, AccessLogRecord } from '@/schemas/access-log';
import UserLabel from './UserLabel';
import {
  ACCESS_LOG_TIME_FORMAT,
  availableTimeZones,
  filterTime,
  formatLogTime,
  systemTimeZone,
} from './timeZone';
import './AccessLogsPage.css';

interface FilterValues {
  nodeGuid?: string;
  timeRange?: [Dayjs | null, Dayjs | null];
  user?: string;
  source?: string;
  target?: string;
  inbound?: string;
  outbound?: string;
  category?: AccessLogQuery['category'];
}

export default function AccessLogsPage() {
  const { t } = useTranslation();
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const [search, setSearch] = useSearchParams();
  const shared = readSharedFilters(search);
  const [form] = Form.useForm<FilterValues>();
  const [params, setParams] = useState<AccessLogQuery>(() => ({
    page: 1,
    pageSize: 50,
    ...shared,
    userExact: shared.user ? true : undefined,
  }));
  const logs = useAccessLogs(params);
  const nodes = useAccessLogNodes();
  const userComments = useMemo(
    () => new Map(Object.entries(logs.data?.userComments ?? {})),
    [logs.data?.userComments],
  );
  const [selectedTimeZone, setSelectedTimeZone] = useState(() => validTimeZone(search.get('zone')));
  const localZone = systemTimeZone();
  const timeZone = selectedTimeZone === 'system' ? localZone : selectedTimeZone;
  const timeZoneOptions = useMemo(
    () => [
      { value: 'system', label: t('accessLogs.systemTimeZone', { zone: localZone }) },
      ...availableTimeZones(localZone).map((zone) => ({ value: zone, label: zone })),
    ],
    [localZone, t],
  );
  const [userOpen, setUserOpen] = useState(false);
  const [userSearch, setUserSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [selectedUser, setSelectedUser] = useState<{ email: string; comment: string } | null>(null);
  useEffect(() => {
    const timeout = setTimeout(() => setDebouncedSearch(userSearch.trim()), 250);
    return () => clearTimeout(timeout);
  }, [userSearch]);
  const users = useAccessLogUsers(debouncedSearch, userOpen);
  const userOptions = useMemo(() => {
    const labels = new Map<string, string>();
    if (selectedUser) labels.set(selectedUser.email, selectedUser.comment);
    for (const page of users.data?.pages ?? []) {
      for (const user of page.items) labels.set(user.email, user.comment ?? '');
    }
    for (const record of logs.data?.items ?? []) {
      if (
        record.email &&
        (!debouncedSearch || record.email.toLowerCase().includes(debouncedSearch.toLowerCase()))
      ) {
        labels.set(record.email, userComments.get(record.email) ?? labels.get(record.email) ?? '');
      }
    }
    return [...labels].map(([email, comment]) => ({ value: email, label: email, comment }));
  }, [users.data, logs.data, selectedUser, debouncedSearch, userComments]);
  const userLabels = useMemo(
    () => new Map(userOptions.map((user) => [user.value, user.comment])),
    [userOptions],
  );
  const nodeOptions = useMemo(
    () =>
      (nodes.data ?? []).map((node) => ({
        value: node.guid,
        label: node.local ? t('accessLogs.localNode') : node.name || node.guid,
      })),
    [nodes.data, t],
  );
  const nodeLabels = useMemo(
    () => new Map(nodeOptions.map((option) => [option.value, option.label])),
    [nodeOptions],
  );

  const columns = useMemo<TableColumnsType<AccessLogRecord>>(() => {
    const text = (value: string) => value || '—';
    return [
      {
        title: t('accessLogs.time'),
        dataIndex: 'occurredAt',
        width: 190,
        render: (value: number) => formatLogTime(value, timeZone),
      },
      {
        title: t('accessLogs.node'),
        dataIndex: 'nodeGuid',
        width: 160,
        ellipsis: true,
        render: (guid: string) => <Tooltip title={guid}>{nodeLabels.get(guid) || guid}</Tooltip>,
      },
      {
        title: t('accessLogs.user'),
        dataIndex: 'email',
        width: 300,
        render: (email: string) => <UserLabel email={email} comment={userComments.get(email)} />,
      },
      { title: t('accessLogs.source'), dataIndex: 'source', width: 220, ellipsis: true },
      { title: t('accessLogs.target'), dataIndex: 'target', width: 240, ellipsis: true },
      {
        title: t('accessLogs.inbound'),
        dataIndex: 'inbound',
        width: 160,
        ellipsis: true,
        render: text,
      },
      {
        title: t('accessLogs.outbound'),
        dataIndex: 'outbound',
        width: 160,
        ellipsis: true,
        render: text,
      },
      {
        title: t('accessLogs.category'),
        dataIndex: 'category',
        width: 110,
        render: (category: AccessLogRecord['category']) => (
          <Tag color={{ direct: 'green', blocked: 'red', proxy: 'blue' }[category]}>
            {t(`accessLogs.${category}`)}
          </Tag>
        ),
      },
    ];
  }, [t, nodeLabels, timeZone, userComments]);

  function changeTimeZone(value: string) {
    const nextZone = value === 'system' ? localZone : value;
    const range = form.getFieldValue('timeRange');
    if (range) {
      form.setFieldValue(
        'timeRange',
        range.map((date: Dayjs | null) => {
          const timestamp = filterTime(date, timeZone);
          return timestamp === undefined ? date : dayjs(timestamp).tz(nextZone);
        }),
      );
      form.setFields([{ name: 'timeRange', errors: [] }]);
    }
    setSelectedTimeZone(value);
    setSearch(writeSharedFilters(search, params, value), { replace: true });
  }

  function apply(values: FilterValues) {
    const { timeRange } = values;
    const next: AccessLogQuery = {
      page: 1,
      pageSize: params.pageSize,
      nodeGuid: values.nodeGuid,
      from: filterTime(timeRange?.[0], timeZone),
      to: filterTime(timeRange?.[1], timeZone),
      user: values.user,
      userExact: values.user ? true : undefined,
      source: values.source,
      target: values.target,
      inbound: values.inbound,
      outbound: values.outbound,
      category: values.category,
    };
    for (const key of ['user', 'source', 'target', 'inbound', 'outbound'] as const) {
      next[key] = next[key]?.trim() || undefined;
    }
    // A repeated search still refreshes an unchanged query.
    if (JSON.stringify(next) === JSON.stringify(params)) void logs.refetch();
    setParams(next);
    setSearch(writeSharedFilters(search, next, selectedTimeZone), { replace: true });
  }

  const error = logs.isError || nodes.isError;
  return (
    <ConfigProvider theme={antdThemeConfig}>
      <Layout
        className={`access-logs-page${isDark ? ' is-dark' : ''}${isUltra ? ' is-ultra' : ''}`}
      >
        <AppSidebar />
        <Layout className="content-shell">
          <Layout.Content id="content-layout" className="content-area">
            <Card
              title={t('accessLogs.title')}
              extra={
                <Button
                  icon={<ReloadOutlined aria-hidden />}
                  loading={logs.isFetching || nodes.isFetching}
                  onClick={() => {
                    void logs.refetch();
                    void nodes.refetch();
                    if (userOpen) void users.refetch();
                  }}
                >
                  {t('refresh')}
                </Button>
              }
            >
              <AnalysisNavigation />
              <Form
                form={form}
                layout="vertical"
                initialValues={{
                  ...shared,
                  timeRange: [
                    shared.from ? dayjs(shared.from).tz(timeZone) : null,
                    shared.to ? dayjs(shared.to).tz(timeZone) : null,
                  ],
                }}
                onFinish={apply}
              >
                <div className="access-log-filters">
                  <Form.Item name="nodeGuid" label={t('accessLogs.node')}>
                    <Select
                      allowClear
                      showSearch={{ optionFilterProp: 'label' }}
                      placeholder={t('all')}
                      options={nodeOptions}
                      loading={nodes.isFetching}
                    />
                  </Form.Item>
                  <Form.Item name="user" label={t('accessLogs.user')}>
                    <Select
                      className="access-log-user-select"
                      allowClear
                      virtual={false}
                      classNames={{ popup: { root: 'access-log-user-popup' } }}
                      options={userOptions}
                      placeholder={t('accessLogs.selectUser')}
                      loading={users.isFetching}
                      showSearch={{
                        searchValue: userSearch,
                        onSearch: setUserSearch,
                        filterOption: false,
                      }}
                      onOpenChange={setUserOpen}
                      onChange={(value) => {
                        setSelectedUser(
                          value ? { email: value, comment: userLabels.get(value) ?? '' } : null,
                        );
                        setUserSearch('');
                      }}
                      optionRender={(option) => (
                        <UserLabel email={option.data.value} comment={option.data.comment} />
                      )}
                      labelRender={({ value }) => (
                        <UserLabel email={String(value)} comment={userLabels.get(String(value))} />
                      )}
                      notFoundContent={users.isError ? t('accessLogs.userLoadError') : undefined}
                      onPopupScroll={(event) => {
                        const element = event.currentTarget;
                        if (
                          element.scrollTop + element.clientHeight >= element.scrollHeight - 40 &&
                          users.hasNextPage &&
                          !users.isFetching
                        ) {
                          void users.fetchNextPage();
                        }
                      }}
                    />
                  </Form.Item>
                  <Form.Item label={t('accessLogs.timeZone')}>
                    <Select
                      id="access-log-time-zone"
                      aria-label={t('accessLogs.timeZone')}
                      value={selectedTimeZone}
                      options={timeZoneOptions}
                      showSearch={{ optionFilterProp: 'label' }}
                      onChange={changeTimeZone}
                    />
                  </Form.Item>
                  <Form.Item
                    name="timeRange"
                    label={t('accessLogs.timeRange')}
                    className="access-log-time-range"
                    rules={[
                      {
                        validator: (_, range: FilterValues['timeRange']) => {
                          const from = filterTime(range?.[0], timeZone);
                          const to = filterTime(range?.[1], timeZone);
                          if (
                            (range?.[0] && from === undefined) ||
                            (range?.[1] && to === undefined)
                          ) {
                            return Promise.reject(new Error(t('accessLogs.invalidLocalTime')));
                          }
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
                      defaultPickerValue={[dayjs().tz(timeZone), dayjs().tz(timeZone)]}
                      classNames={{ popup: { root: 'access-log-time-popup' } }}
                    />
                  </Form.Item>
                  <Form.Item name="category" label={t('accessLogs.category')}>
                    <Select
                      allowClear
                      placeholder={t('all')}
                      options={(['direct', 'proxy', 'blocked'] as const).map((value) => ({
                        value,
                        label: t(`accessLogs.${value}`),
                      }))}
                    />
                  </Form.Item>
                  {(['source', 'target', 'inbound', 'outbound'] as const).map((key) => (
                    <Form.Item key={key} name={key} label={t(`accessLogs.${key}`)}>
                      <Input allowClear maxLength={512} placeholder={t('accessLogs.contains')} />
                    </Form.Item>
                  ))}
                  <Space wrap className="access-log-actions">
                    <Button type="primary" htmlType="submit" icon={<SearchOutlined aria-hidden />}>
                      {t('search')}
                    </Button>
                    <Button
                      onClick={() => {
                        form.setFieldsValue({
                          nodeGuid: undefined,
                          user: undefined,
                          category: undefined,
                          timeRange: undefined,
                          source: undefined,
                          target: undefined,
                          inbound: undefined,
                          outbound: undefined,
                        });
                        setSearch(writeSharedFilters(search, {}, selectedTimeZone), {
                          replace: true,
                        });
                        setSelectedUser(null);
                        setUserSearch('');
                        setParams({ page: 1, pageSize: params.pageSize });
                      }}
                    >
                      {t('reset')}
                    </Button>
                  </Space>
                </div>
              </Form>
              {error && (
                <Alert
                  type="error"
                  showIcon
                  title={t('accessLogs.loadError')}
                  className="access-log-error"
                />
              )}
              <Table<AccessLogRecord>
                rowKey="id"
                size="small"
                columns={columns}
                dataSource={logs.data?.items ?? []}
                loading={logs.isFetching}
                scroll={{ x: 1400 }}
                locale={{ emptyText: t('accessLogs.empty') }}
                pagination={{
                  current: logs.data?.page ?? params.page,
                  pageSize: params.pageSize,
                  total: logs.data?.total ?? 0,
                  showSizeChanger: true,
                  showQuickJumper: true,
                  pageSizeOptions: [25, 50, 100, 200],
                  showTotal: (total) => t('accessLogs.total', { count: total }),
                  onChange: (page, pageSize) =>
                    setParams((current) => ({
                      ...current,
                      page: pageSize === current.pageSize ? page : 1,
                      pageSize,
                    })),
                }}
              />
            </Card>
          </Layout.Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
