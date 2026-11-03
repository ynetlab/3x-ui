import { useMemo, useState } from 'react';
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
  Typography,
  Alert,
} from 'antd';
import type { TableColumnsType } from 'antd';
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import dayjs from 'dayjs';
import type { Dayjs } from 'dayjs';

import AppSidebar from '@/layouts/AppSidebar';
import { useTheme } from '@/hooks/useTheme';
import { useAccessLogNodes, useAccessLogs } from '@/api/queries/useAccessLogs';
import type { AccessLogQuery, AccessLogRecord } from '@/schemas/access-log';
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
  const [form] = Form.useForm<FilterValues>();
  const [params, setParams] = useState<AccessLogQuery>({ page: 1, pageSize: 50 });
  const logs = useAccessLogs(params);
  const nodes = useAccessLogNodes();
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
        render: (value: number) => dayjs(value).format('YYYY-MM-DD HH:mm:ss'),
      },
      {
        title: t('accessLogs.node'),
        dataIndex: 'nodeGuid',
        width: 160,
        ellipsis: true,
        render: (guid: string) => <Tooltip title={guid}>{nodeLabels.get(guid) || guid}</Tooltip>,
      },
      { title: t('accessLogs.user'), dataIndex: 'email', width: 160, ellipsis: true, render: text },
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
  }, [t, nodeLabels]);

  function apply(values: FilterValues) {
    const { timeRange } = values;
    const next: AccessLogQuery = {
      page: 1,
      pageSize: params.pageSize,
      nodeGuid: values.nodeGuid,
      from: timeRange?.[0]?.valueOf(),
      to: timeRange?.[1]?.valueOf(),
      user: values.user,
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
                  }}
                >
                  {t('refresh')}
                </Button>
              }
            >
              <Typography.Paragraph type="secondary">
                {t('accessLogs.subtitle')}
              </Typography.Paragraph>
              <Form form={form} layout="vertical" onFinish={apply}>
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
                  <Form.Item
                    name="timeRange"
                    label={t('accessLogs.timeRange')}
                    className="access-log-time-range"
                    rules={[
                      {
                        validator: (_, range: FilterValues['timeRange']) =>
                          !range?.[0] || !range?.[1] || range[0].valueOf() <= range[1].valueOf()
                            ? Promise.resolve()
                            : Promise.reject(new Error(t('accessLogs.invalidTimeRange'))),
                      },
                    ]}
                  >
                    <DatePicker.RangePicker
                      showTime
                      allowEmpty={[true, true]}
                      format="YYYY-MM-DD HH:mm:ss"
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
                  {(['user', 'source', 'target', 'inbound', 'outbound'] as const).map((key) => (
                    <Form.Item key={key} name={key} label={t(`accessLogs.${key}`)}>
                      <Input allowClear maxLength={512} placeholder={t('accessLogs.contains')} />
                    </Form.Item>
                  ))}
                </div>
                <Space wrap className="access-log-actions">
                  <Button type="primary" htmlType="submit" icon={<SearchOutlined aria-hidden />}>
                    {t('search')}
                  </Button>
                  <Button
                    onClick={() => {
                      form.resetFields();
                      setParams({ page: 1, pageSize: params.pageSize });
                    }}
                  >
                    {t('reset')}
                  </Button>
                </Space>
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
