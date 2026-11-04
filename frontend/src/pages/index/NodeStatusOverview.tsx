import { lazy, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Alert, Button, Dropdown, Modal, Space, Tag, Tooltip } from 'antd';
import type { MenuProps } from 'antd';
import { useTranslation } from 'react-i18next';
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  CloudServerOutlined,
  CopyOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  DownloadOutlined,
  EyeInvisibleOutlined,
  EyeOutlined,
  HddOutlined,
  MoreOutlined,
  PoweroffOutlined,
  ReloadOutlined,
  SwapOutlined,
} from '@ant-design/icons';

import { NodeTargetContext, useNodeTarget } from '@/api/nodeTarget';
import { useStatusQuery } from '@/api/queries/useStatusQuery';
import type { NodeRecord } from '@/schemas/node';
import type { Status } from '@/models/status';
import {
  ClipboardManager,
  CPUFormatter,
  FileManager,
  HttpUtil,
  SizeFormatter,
  TimeFormatter,
} from '@/utils';
import { LazyMount } from '@/components/utility';
import './NodeStatusOverview.css';

const TrafficQuotaModal = lazy(() => import('./TrafficQuotaModal'));
const LogModal = lazy(() => import('./LogModal'));
const XrayLogModal = lazy(() => import('./XrayLogModal'));
const SystemHistoryModal = lazy(() => import('./SystemHistoryModal'));
const XrayMetricsModal = lazy(() => import('./XrayMetricsModal'));
const JsonEditor = lazy(() => import('@/components/form/JsonEditor'));
const NodeUpdateModal = lazy(() => import('./NodeUpdateModal'));

type DetailKind = 'logs' | 'access' | 'config' | 'history' | 'metrics';
interface DetailTarget {
  nodeId?: number;
  name: string;
  kind: DetailKind;
  status: Status;
}
interface OverviewProps {
  nodes: NodeRecord[];
  masterVersion: string;
  onMasterBackup: () => void;
  onMasterPanelUpdate: () => void;
  onMasterVersionSwitch: () => void;
  onMasterAmneziaWGLogs: () => void;
}

function ResourceMeter({
  label,
  percent,
  detail,
  icon,
}: {
  label: string;
  percent?: number;
  detail: string;
  icon: ReactNode;
}) {
  const value = percent === undefined ? undefined : Math.max(0, Math.min(100, percent));
  return (
    <div className="node-resource">
      <div className="node-resource-label">
        {icon}
        <span>{label}</span>
        <strong>{value === undefined ? '—' : `${value.toFixed(1)}%`}</strong>
      </div>
      <div
        className="node-resource-track"
        aria-label={label}
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={value}
      >
        <span
          style={{
            width: `${value ?? 0}%`,
            background:
              value !== undefined && value >= 90
                ? 'var(--ant-color-error)'
                : value !== undefined && value >= 80
                  ? 'var(--ant-color-warning)'
                  : undefined,
          }}
        />
      </div>
      <div className="node-resource-detail">{detail}</div>
    </div>
  );
}

function NodeStatusCard({
  node,
  showAddress,
  masterVersion,
  onDetails,
  ...masterActions
}: Omit<OverviewProps, 'nodes'> & {
  node?: NodeRecord;
  showAddress: boolean;
  onDetails: (detail: DetailTarget) => void;
}) {
  const { t } = useTranslation();
  const target = useNodeTarget();
  const indirect = !!node && (!!node.transitive || !Number.isSafeInteger(node.id) || node.id <= 0);
  const disabled = node?.enable === false;
  const { status, fetched, fetchError, refresh } = useStatusQuery({
    enabled: !indirect && !disabled,
  });
  const [quotaOpen, setQuotaOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [updateKind, setUpdateKind] = useState<'panel' | 'version' | null>(null);
  const [updateOpen, setUpdateOpen] = useState(false);
  const openUpdate = (kind: 'panel' | 'version') => {
    setUpdateKind(kind);
    setUpdateOpen(true);
  };
  const name = node?.name || (node ? `#${node.id}` : t('nodeStatus.master'));
  const ready = fetched && !fetchError && !disabled && !indirect;
  const cached = indirect && node?.status === 'online';
  const connection = disabled
    ? 'disabled'
    : fetchError
      ? 'offline'
      : ready
        ? 'online'
        : node?.status || 'connecting';
  const coreState = ready ? status.xray.state : cached ? node?.xrayState : 'unknown';
  const stateKey =
    coreState === 'running'
      ? 'pages.index.xrayStatusRunning'
      : coreState === 'stop'
        ? 'pages.index.xrayStatusStop'
        : coreState === 'error'
          ? 'pages.index.xrayStatusError'
          : 'pages.index.xrayStatusUnknown';
  const unavailable = !ready || disabled || indirect;
  const amount = (current: number, total: number) =>
    ready && total > 0
      ? `${SizeFormatter.sizeFormat(current)} / ${SizeFormatter.sizeFormat(total)}`
      : '—';
  const metric = (key: string) => ready && status.metricAvailable(key);
  const openDetail = (kind: DetailKind) => onDetails({ nodeId: target.nodeId, name, kind, status });
  const details: MenuProps['items'] = [
    ...(!node
      ? [
          {
            key: 'trafficQuota',
            label: t('nodeStatus.trafficSettings'),
            onClick: () => setQuotaOpen(true),
          },
        ]
      : []),
    { key: 'logs', label: t('pages.index.logs'), onClick: () => openDetail('logs') },
    { key: 'access', label: t('pages.index.accessLogs'), onClick: () => openDetail('access') },
    { key: 'config', label: t('pages.index.config'), onClick: () => openDetail('config') },
    ...(!node
      ? [
          {
            key: 'backup',
            label: t('pages.index.backupTitle'),
            onClick: masterActions.onMasterBackup,
          },
        ]
      : []),
    {
      key: 'history',
      label: t('pages.index.systemHistoryTitle'),
      onClick: () => openDetail('history'),
    },
    {
      key: 'metrics',
      label: t('pages.index.xrayMetricsTitle'),
      onClick: () => openDetail('metrics'),
    },
    { type: 'divider' as const },
    {
      key: 'panelUpdate',
      label: t('pages.index.updatePanel'),
      onClick: node ? () => openUpdate('panel') : masterActions.onMasterPanelUpdate,
    },
    {
      key: 'version',
      label: t('pages.index.xraySwitch'),
      onClick: node ? () => openUpdate('version') : masterActions.onMasterVersionSwitch,
    },
    ...(!node && status.amneziawg.configured
      ? [
          {
            key: 'amneziawg',
            label: t('pages.index.amneziawgLogs'),
            onClick: masterActions.onMasterAmneziaWGLogs,
          },
        ]
      : []),
  ];

  async function command(action: 'restartXrayService' | 'stopXrayService') {
    setBusy(action);
    try {
      const result = await HttpUtil.post(target.url(`/panel/api/server/${action}`));
      if (result?.success) await refresh();
    } finally {
      setBusy(null);
    }
  }

  const quota = node ?? status.trafficQuota;
  const trafficLimit = quota?.trafficLimit ?? 0;
  const trafficUsage = quota?.trafficUsage;
  const displayedTraffic =
    trafficLimit > 0 ? trafficUsage : ready ? status.protocolTraffic : undefined;
  const trafficUsed = trafficUsage ? trafficUsage.up + trafficUsage.down : undefined;
  const trafficPercent =
    trafficUsed === undefined || trafficLimit <= 0 ? undefined : (trafficUsed / trafficLimit) * 100;
  const coreError = ready ? status.xray.errorMsg : fetchError || node?.lastError;
  return (
    <article className="node-status-card" data-connection={connection} aria-label={name}>
      <div className="node-card-toolbar">
        <Tag variant="filled" color={!node ? 'blue' : undefined}>
          {!node
            ? t('nodeStatus.master')
            : t(indirect ? 'nodeStatus.indirect' : 'nodeStatus.child')}
        </Tag>
        <Space size={4}>
          <Tooltip title={t('pages.index.restartXray')}>
            <Button
              size="small"
              icon={<ReloadOutlined aria-hidden />}
              disabled={unavailable || !!busy}
              loading={busy === 'restartXrayService'}
              onClick={() => command('restartXrayService')}
            >
              {t('nodeStatus.restart')}
            </Button>
          </Tooltip>
          <Tooltip title={t('pages.index.stopXray')}>
            <Button
              size="small"
              danger
              icon={<PoweroffOutlined aria-hidden />}
              disabled={unavailable || !!busy || coreState === 'stop'}
              loading={busy === 'stopXrayService'}
              onClick={() => command('stopXrayService')}
            >
              {t('nodeStatus.stop')}
            </Button>
          </Tooltip>
          <Dropdown trigger={['click']} menu={{ items: details }} disabled={unavailable || !!busy}>
            <Button
              size="small"
              icon={<MoreOutlined aria-hidden />}
              disabled={unavailable || !!busy}
            >
              {t('nodeStatus.details')}
            </Button>
          </Dropdown>
        </Space>
      </div>
      <div className="node-card-heading">
        <div className="node-card-icon">
          <CloudServerOutlined aria-hidden />
        </div>
        <div className="node-card-identity">
          <h2 title={name}>{name}</h2>
          <span className={showAddress ? 'address-visible' : 'address-hidden'}>
            {node
              ? `${node.address || '—'}${node.port ? `:${node.port}` : ''}`
              : window.location.host}
          </span>
        </div>
        <span className="node-connection">
          <i />
          {t(`nodeStatus.${connection}`, { defaultValue: connection })}
        </span>
      </div>
      <div className="node-card-core">
        <span className={`node-core-dot is-${coreState}`} />
        <span>Xray · {t(stateKey)}</span>
        <span className="node-core-version">
          {ready ? status.xray.version || '—' : node?.xrayVersion || '—'}
        </span>
        {ready && status.resourceScope === 'container' && (
          <Tag variant="filled">{t('nodeStatus.container')}</Tag>
        )}
      </div>
      <div className="node-resources">
        <ResourceMeter
          label={t('pages.index.cpu')}
          icon={<DashboardOutlined aria-hidden />}
          percent={
            metric('cpu')
              ? status.cpu.percent
              : cached && !node?.unavailableMetrics?.includes('cpu')
                ? node?.cpuPct
                : undefined
          }
          detail={
            metric('cpu')
              ? status.resourceScope === 'container'
                ? `${status.logicalPro} vCPU`
                : `${CPUFormatter.cpuCoreFormat(status.cpuCores)} / ${status.logicalPro}T`
              : '—'
          }
        />
        <ResourceMeter
          label={t('pages.index.memory')}
          icon={<DatabaseOutlined aria-hidden />}
          percent={
            ready && status.mem.total > 0 ? status.mem.percent : cached ? node?.memPct : undefined
          }
          detail={amount(status.mem.current, status.mem.total)}
        />
        <ResourceMeter
          label={t('pages.index.swap')}
          icon={<SwapOutlined aria-hidden />}
          percent={metric('swap') ? status.swap.percent : undefined}
          detail={metric('swap') ? amount(status.swap.current, status.swap.total) : '—'}
        />
        <ResourceMeter
          label={t('pages.index.storage')}
          icon={<HddOutlined aria-hidden />}
          percent={ready && status.disk.total > 0 ? status.disk.percent : undefined}
          detail={amount(status.disk.current, status.disk.total)}
        />
      </div>
      <div className="node-network">
        <div>
          <span>
            <ArrowUpOutlined aria-hidden /> {t('pages.index.upload')}
            <small>{displayedTraffic ? SizeFormatter.sizeFormat(displayedTraffic.up) : '—'}</small>
          </span>
          <strong>{ready ? SizeFormatter.speedFormat(status.netIO.up) : '—'}</strong>
        </div>
        <div>
          <span>
            <ArrowDownOutlined aria-hidden /> {t('pages.index.download')}
            <small>
              {displayedTraffic ? SizeFormatter.sizeFormat(displayedTraffic.down) : '—'}
            </small>
          </span>
          <strong>{ready ? SizeFormatter.speedFormat(status.netIO.down) : '—'}</strong>
        </div>
        {trafficLimit > 0 && (
          <div className="node-traffic-quota">
            <span>
              {t('nodeStatus.trafficUsage')}
              <small>
                {trafficUsed === undefined ? '—' : SizeFormatter.sizeFormat(trafficUsed)} /{' '}
                {SizeFormatter.sizeFormat(trafficLimit)}
              </small>
            </span>
            <div
              className="node-resource-track"
              role="progressbar"
              aria-label={t('nodeStatus.trafficUsage')}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={
                trafficPercent === undefined ? undefined : Math.min(100, Math.round(trafficPercent))
              }
            >
              <span
                style={{
                  width: `${Math.min(100, trafficPercent ?? 0)}%`,
                  background: (trafficPercent ?? 0) >= 90 ? 'var(--ant-color-error)' : undefined,
                }}
              />
            </div>
          </div>
        )}
      </div>
      <dl className="node-card-facts">
        <div>
          <dt>{t('nodeStatus.connections')}</dt>
          <dd>
            {metric('tcpCount') ? status.tcpCount : '—'} <small>TCP</small> /{' '}
            {metric('udpCount') ? status.udpCount : '—'} <small>UDP</small>
          </dd>
        </div>
        <div>
          <dt>{t('nodeStatus.load')}</dt>
          <dd>{metric('loads') ? status.loads.join(' / ') : '—'}</dd>
        </div>
        <div>
          <dt>{t('pages.index.uptime')}</dt>
          <dd>
            {metric('uptime')
              ? TimeFormatter.formatSecond(status.uptime)
              : cached && node?.uptimeSecs && !node.unavailableMetrics?.includes('uptime')
                ? TimeFormatter.formatSecond(node.uptimeSecs)
                : '—'}
          </dd>
        </div>
        <div>
          <dt>{t('pages.index.panel')}</dt>
          <dd>
            {ready
              ? `${SizeFormatter.sizeFormat(status.appStats.mem)} · ${status.appStats.threads} ${t('pages.index.threads')}`
              : '—'}
          </dd>
        </div>
      </dl>
      {coreError && (
        <Tooltip title={coreError}>
          <div className="node-card-error">{coreError}</div>
        </Tooltip>
      )}
      {indirect && <div className="node-card-notice">{t('nodeStatus.indirectHint')}</div>}
      <footer>
        <span>{node?.panelVersion || (!node ? masterVersion : '—')}</span>
        <span>Xray {ready ? TimeFormatter.formatSecond(status.appStats.uptime) : '—'}</span>
      </footer>
      {!node && quotaOpen && (
        <LazyMount when={true}>
          <TrafficQuotaModal
            quota={status.trafficQuota}
            onClose={() => setQuotaOpen(false)}
            onSaved={refresh}
          />
        </LazyMount>
      )}
      {node && updateKind && (
        <LazyMount when={true}>
          <NodeUpdateModal
            key={updateKind}
            kind={updateKind}
            open={updateOpen}
            name={name}
            status={status}
            onClose={() => setUpdateOpen(false)}
            onBusy={(updating) => setBusy(updating ? 'update' : null)}
            onUpdated={refresh}
          />
        </LazyMount>
      )}
    </article>
  );
}

function ConfigModal({ name, onClose }: { name: string; onClose: () => void }) {
  const { t } = useTranslation();
  const target = useNodeTarget();
  const [text, setText] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let cancelled = false;
    void HttpUtil.get(target.url('/panel/api/server/getConfigJson')).then((result) => {
      if (cancelled) return;
      if (result?.success) setText(JSON.stringify(result.obj, null, 2));
      else setError(result?.msg || t('somethingWentWrong'));
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [target, t]);
  return (
    <Modal
      open
      title={`${t('pages.index.config')} · ${name}`}
      onCancel={onClose}
      width={900}
      loading={loading}
      footer={[
        <Button
          key="download"
          icon={<DownloadOutlined aria-hidden />}
          disabled={!text}
          onClick={() =>
            FileManager.downloadTextFile(text, `config-${target.nodeId ?? 'master'}.json`)
          }
        >
          {t('download')}
        </Button>,
        <Button
          key="copy"
          icon={<CopyOutlined aria-hidden />}
          disabled={!text}
          onClick={() => ClipboardManager.copyText(text)}
        >
          {t('copy')}
        </Button>,
      ]}
    >
      {error ? (
        <Alert type="error" showIcon title={error} />
      ) : (
        <JsonEditor value={text} onChange={setText} readOnly minHeight="360px" maxHeight="65vh" />
      )}
    </Modal>
  );
}

export default function NodeStatusOverview({ nodes, ...masterProps }: OverviewProps) {
  const { t } = useTranslation();
  const [detail, setDetail] = useState<DetailTarget | null>(null);
  const [showAddress, setShowAddress] = useState(false);
  const close = () => setDetail(null);
  return (
    <section className="node-status-overview">
      <header className="node-status-header">
        <div>
          <span className="node-status-eyebrow">{t('nodeStatus.live')}</span>
          <div className="node-status-title">
            <h1>{t('nodeStatus.title')}</h1>
            <Tooltip title={t('pages.index.toggleIpVisibility')}>
              <Button
                type="text"
                size="small"
                aria-label={t('pages.index.toggleIpVisibility')}
                aria-pressed={showAddress}
                icon={
                  showAddress ? <EyeOutlined aria-hidden /> : <EyeInvisibleOutlined aria-hidden />
                }
                onClick={() => setShowAddress((value) => !value)}
              />
            </Tooltip>
          </div>
          <p>{t('nodeStatus.subtitle')}</p>
        </div>
        <Tag>{t('nodeStatus.panelCount', { count: nodes.length + 1 })}</Tag>
      </header>
      <div className="node-status-grid">
        <NodeTargetContext.Provider value={undefined}>
          <NodeStatusCard {...masterProps} showAddress={showAddress} onDetails={setDetail} />
        </NodeTargetContext.Provider>
        {nodes.map((node) => (
          <NodeTargetContext.Provider
            key={node.transitive ? node.guid || `${node.parentGuid}-${node.name}` : node.id}
            value={node.transitive || node.id <= 0 ? undefined : node.id}
          >
            <NodeStatusCard
              node={node}
              {...masterProps}
              showAddress={showAddress}
              onDetails={setDetail}
            />
          </NodeTargetContext.Provider>
        ))}
      </div>
      {detail && (
        <NodeTargetContext.Provider
          key={`${detail.nodeId ?? 'master'}-${detail.kind}`}
          value={detail.nodeId}
        >
          <LazyMount when={true}>
            {detail.kind === 'logs' && <LogModal open onClose={close} targetName={detail.name} />}
            {detail.kind === 'access' && (
              <XrayLogModal open onClose={close} targetName={detail.name} />
            )}
            {detail.kind === 'config' && <ConfigModal name={detail.name} onClose={close} />}
            {detail.kind === 'history' && (
              <SystemHistoryModal
                open
                status={detail.status}
                onClose={close}
                targetName={detail.name}
              />
            )}
            {detail.kind === 'metrics' && (
              <XrayMetricsModal open onClose={close} targetName={detail.name} />
            )}
          </LazyMount>
        </NodeTargetContext.Provider>
      )}
    </section>
  );
}
