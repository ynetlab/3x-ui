import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Button,
  Modal,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import type { TableColumnsType } from 'antd';
import {
  CloudOutlined,
  DeleteOutlined,
  EditOutlined,
  LinkOutlined,
  PlusOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import dayjs from 'dayjs';

import type { NodeRecord } from '@/schemas/node';
import type { NodeDNSInput, NodeDNSRecord } from '@/schemas/node-dns';
import { useNodeDNS, NodeDNSRequestError, type NodeDNSOperation } from '@/api/queries/useNodeDNS';
import { nodeDNSCertificateDomains, nodeDNSSelectable } from '@/lib/nodes/dns';
import NodeDNSRecordForm from './NodeDNSRecordForm';
import NodeCertificatePanel from './NodeCertificatePanel';
import './NodeDNSModal.css';

const EMPTY_RECORDS: NodeDNSRecord[] = [];
interface Props {
  node: NodeRecord;
  nodes?: NodeRecord[];
  onClose: () => void;
}

// A new identity gets a new query/editor/selection lifetime, even if a caller
// changes the selected node without first unmounting the dialog.
export default function NodeDNSModal(props: Props) {
  return <NodeDNSDialog key={`${props.node.id}:${props.node.guid ?? ''}`} {...props} />;
}

function NodeDNSDialog({ node, nodes = [], onClose }: Props) {
  const { t } = useTranslation();
  const { records: query, publicIP, mutation, refresh } = useNodeDNS(node);
  const [modal, modalContext] = Modal.useModal();
  const [messageApi, messageContext] = message.useMessage();
  const [editor, setEditor] = useState<{ record?: NodeDNSRecord } | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [lastCreate, setLastCreate] = useState<NodeDNSInput | null>(null);
  const records = query.data?.records ?? EMPTY_RECORDS;
  const [selectionSource, setSelectionSource] = useState(records);
  const ip = publicIP.data ?? query.data?.publicIp;
  const busy = mutation.isPending;
  const stale =
    !!ip?.receivedAt &&
    Math.max(publicIP.dataUpdatedAt, query.dataUpdatedAt) - ip.receivedAt > 120_000;
  const writable = !!query.data && !query.isError && !query.isFetching && !busy;
  const actionDisabled = !writable || !!editor;
  const selectedRecords = records.filter(
    (record) => selected.includes(record.id) && nodeDNSSelectable(record),
  );
  const domains = nodeDNSCertificateDomains(selectedRecords);
  const ownerExists = (record: NodeDNSRecord) =>
    !!record.ownerNodeId &&
    record.ownerNodeId !== node.id &&
    nodes.some((owner) => !owner.transitive && owner.id === record.ownerNodeId);
  const errorText = (error: unknown) =>
    t(`nodeDNS.errors.${error instanceof Error ? error.message : ''}`, {
      defaultValue: t('nodeDNS.errors.requestFailed'),
    });

  if (selectionSource !== records) {
    setSelectionSource(records);
    const allowed = new Set(records.filter(nodeDNSSelectable).map((record) => record.id));
    setSelected((previous) => {
      const next = previous.filter((id) => allowed.has(id));
      return next.length === previous.length ? previous : next;
    });
  }

  async function perform(operation: NodeDNSOperation): Promise<boolean> {
    try {
      await mutation.mutateAsync(operation);
      messageApi.success(t(`nodeDNS.success.${operation.action}`));
      return true;
    } catch {
      return false;
    }
  }
  async function save(input: NodeDNSInput) {
    if (!editor) return;
    if (!editor.record) setLastCreate(input);
    const operation: NodeDNSOperation = editor.record
      ? { action: 'update', recordId: editor.record.id, input }
      : { action: 'create', input };
    if (await perform(operation)) setEditor(null);
  }
  function bind(
    record: Pick<NodeDNSRecord, 'id' | 'name' | 'type' | 'content'>,
    closeEditor = false,
  ) {
    modal.confirm({
      title: t('nodeDNS.bindConfirm'),
      content: (
        <>
          <Typography.Paragraph>
            {record.name} · {record.type} · {record.content}
          </Typography.Paragraph>
          <Typography.Paragraph>{t('nodeDNS.bindHint')}</Typography.Paragraph>
        </>
      ),
      okText: t('nodeDNS.bind'),
      cancelText: t('cancel'),
      onOk: async () => {
        if (
          (await perform({
            action: 'bind',
            recordId: record.id,
            input: { content: record.content },
          })) &&
          closeEditor
        )
          setEditor(null);
      },
    });
  }
  function remove(record: NodeDNSRecord) {
    modal.confirm({
      title: t(record.missing ? 'nodeDNS.clearBinding' : 'nodeDNS.deleteRecord'),
      content: (
        <>
          <Typography.Paragraph>
            {record.name} · {record.type} · {record.content}
          </Typography.Paragraph>
          <Typography.Paragraph>
            {t(record.missing ? 'nodeDNS.clearBindingHint' : 'nodeDNS.deleteHint')}
          </Typography.Paragraph>
        </>
      ),
      okText: t('delete'),
      cancelText: t('cancel'),
      okButtonProps: { danger: true },
      onOk: async () => {
        await perform({ action: 'delete', recordId: record.id });
      },
    });
  }

  const columns: TableColumnsType<NodeDNSRecord> = [
    {
      title: t('nodeDNS.domain'),
      dataIndex: 'name',
      width: 235,
      render: (name: string) => <span className="node-dns-domain">{name}</span>,
    },
    { title: t('nodeDNS.type'), dataIndex: 'type', width: 80 },
    {
      title: t('nodeDNS.targetIP'),
      dataIndex: 'content',
      width: 220,
      render: (content: string) => <span className="node-dns-address">{content}</span>,
    },
    {
      title: t('nodeDNS.ttl'),
      dataIndex: 'ttl',
      width: 85,
      render: (ttl: number) => (ttl === 1 ? t('nodeDNS.automatic') : `${ttl}s`),
    },
    {
      title: t('nodeDNS.proxy'),
      dataIndex: 'proxied',
      width: 110,
      render: (_, record) => (
        <Switch
          size="small"
          checked={record.proxied}
          checkedChildren={<CloudOutlined aria-hidden />}
          disabled={
            actionDisabled ||
            !record.bound ||
            record.missing ||
            (!!node.controlConnection && record.name === node.address) ||
            !['A', 'AAAA'].includes(record.type) ||
            (!record.proxiable && !record.proxied)
          }
          loading={
            busy &&
            mutation.variables?.action === 'proxied' &&
            'recordId' in mutation.variables &&
            mutation.variables.recordId === record.id
          }
          aria-label={t('nodeDNS.proxyFor', { domain: record.name, type: record.type })}
          onChange={(proxied) => {
            void perform({ action: 'proxied', recordId: record.id, input: { proxied } });
          }}
        />
      ),
    },
    {
      title: t('status'),
      width: 180,
      render: (_, record) => (
        <Space size={[0, 4]} wrap>
          <Tag color={record.bound ? 'green' : 'default'}>
            {t(record.bound ? 'nodeDNS.bound' : 'nodeDNS.unbound')}
          </Tag>
          {record.ownerNodeId && record.ownerNodeId !== node.id ? (
            <Tag>{t('nodeDNS.otherOwner', { id: record.ownerNodeId })}</Tag>
          ) : null}
          {record.missing && <Tag color="red">{t('nodeDNS.missing')}</Tag>}
          {record.changed && <Tag color="orange">{t('nodeDNS.changed')}</Tag>}
          {!['A', 'AAAA'].includes(record.type) && (
            <Tag color="red">{t('nodeDNS.unsupported')}</Tag>
          )}
          {record.lastSyncError && (
            <Tooltip title={errorText(new Error(record.lastSyncError))}>
              <Tag color="red">{t('nodeDNS.syncFailed')}</Tag>
            </Tooltip>
          )}
        </Space>
      ),
    },
    {
      title: t('pages.nodes.actions'),
      width: 165,
      render: (_, record) => {
        const supported = ['A', 'AAAA'].includes(record.type);
        return (
          <Space size={4} wrap>
            {(!record.bound || record.changed) && !record.missing && supported && (
              <Button
                size="small"
                disabled={actionDisabled || ownerExists(record)}
                icon={<LinkOutlined aria-hidden />}
                onClick={() => bind(record)}
              >
                {t(record.bound ? 'nodeDNS.confirmBinding' : 'nodeDNS.bind')}
              </Button>
            )}
            {record.bound && supported && (
              <>
                {!record.missing && (
                  <Tooltip title={t('edit')}>
                    <Button
                      size="small"
                      aria-label={t('nodeDNS.editFor', { domain: record.name, type: record.type })}
                      icon={<EditOutlined aria-hidden />}
                      disabled={actionDisabled}
                      onClick={() => {
                        mutation.reset();
                        setEditor({ record });
                      }}
                    />
                  </Tooltip>
                )}
                <Tooltip title={t(record.missing ? 'nodeDNS.clearBinding' : 'delete')}>
                  <Button
                    size="small"
                    danger
                    aria-label={t('nodeDNS.deleteFor', { domain: record.name, type: record.type })}
                    icon={<DeleteOutlined aria-hidden />}
                    disabled={actionDisabled}
                    onClick={() => remove(record)}
                  />
                </Tooltip>
              </>
            )}
          </Space>
        );
      },
    },
  ];
  const selectableIds = useMemo(
    () => new Set(records.filter(nodeDNSSelectable).map((record) => record.id)),
    [records],
  );
  const queryError = query.error || mutation.error;
  const recoverRecordId =
    editor &&
    !editor.record &&
    lastCreate?.content &&
    mutation.error instanceof NodeDNSRequestError &&
    ['cloudflare_record_exists', 'cloudflare_binding_save_failed'].includes(mutation.error.message)
      ? mutation.error.recordId
      : undefined;
  return (
    <Modal
      open
      title={t('nodeDNS.dialogTitle', { name: node.name || node.address || node.id })}
      width="min(1160px, calc(100vw - 24px))"
      className="node-dns-modal"
      styles={{ body: { maxHeight: '72vh', overflowY: 'auto' } }}
      destroyOnHidden
      closable={!busy}
      mask={{ closable: !busy }}
      keyboard={!busy}
      onCancel={() => {
        if (!busy) onClose();
      }}
      footer={
        <Button disabled={busy} onClick={onClose}>
          {t('close')}
        </Button>
      }
    >
      {modalContext}
      {messageContext}
      <div className="node-dns-summary">
        {(['ipv4', 'ipv6'] as const).map((family) => (
          <div key={family} className="node-dns-ip">
            <Typography.Text type="secondary">{family.toUpperCase()}</Typography.Text>
            <div className="node-dns-address">{ip?.[family] || t('nodeDNS.noReport')}</div>
            {ip?.[family] &&
              (stale || !ip[family === 'ipv4' ? 'ipv4Available' : 'ipv6Available']) && (
                <Tag color="orange">
                  {t(stale ? 'nodeDNS.staleReport' : 'nodeDNS.ipUnavailable')}
                </Tag>
              )}
          </div>
        ))}
        <div>
          <Typography.Text type="secondary">{t('nodeDNS.zone')}</Typography.Text>
          <div>{query.data?.zoneName || '—'}</div>
        </div>
        <div>
          <Typography.Text type="secondary">{t('nodeDNS.lastReport')}</Typography.Text>
          <div>{ip?.receivedAt ? dayjs(ip.receivedAt).format('YYYY-MM-DD HH:mm:ss') : '—'}</div>
        </div>
      </div>
      <Typography.Paragraph type="secondary">{t('nodeDNS.autoSyncHint')}</Typography.Paragraph>
      {publicIP.isError && <Alert type="warning" showIcon title={t('nodeDNS.ipLoadFailed')} />}
      {queryError && (
        <Alert type="error" showIcon title={errorText(queryError)} className="node-dns-error" />
      )}
      {recoverRecordId && lastCreate?.name && lastCreate.type && lastCreate.content && (
        <Button
          className="node-dns-toolbar"
          disabled={busy || query.isFetching}
          icon={<LinkOutlined aria-hidden />}
          onClick={() =>
            bind(
              {
                id: recoverRecordId,
                name: lastCreate.name!,
                type: lastCreate.type!,
                content: lastCreate.content!,
              },
              true,
            )
          }
        >
          {t('nodeDNS.recoverBinding')}
        </Button>
      )}
      <Space wrap className="node-dns-toolbar">
        <Button
          icon={<ReloadOutlined aria-hidden />}
          disabled={busy}
          loading={query.isFetching || publicIP.isFetching}
          onClick={() => {
            mutation.reset();
            refresh();
          }}
        >
          {t('refresh')}
        </Button>
        <Button
          type="primary"
          icon={<PlusOutlined aria-hidden />}
          disabled={!writable || !!editor}
          onClick={() => {
            mutation.reset();
            setEditor({});
          }}
        >
          {t('nodeDNS.addRecord')}
        </Button>
      </Space>
      {editor && query.data && (
        <NodeDNSRecordForm
          key={editor.record?.id ?? 'new'}
          record={editor.record}
          address={query.data.nodeAddress}
          zone={query.data.zoneName}
          busy={busy}
          disabled={!writable}
          onSave={save}
          onCancel={() => {
            mutation.reset();
            setEditor(null);
          }}
        />
      )}
      <Table<NodeDNSRecord>
        rowKey="id"
        dataSource={records}
        columns={columns}
        size="small"
        scroll={{ x: 1110 }}
        loading={query.isFetching}
        rowSelection={{
          selectedRowKeys: selected.filter((id) => selectableIds.has(id)),
          preserveSelectedRowKeys: true,
          onChange: (keys) =>
            setSelected(
              keys.filter(
                (key): key is string => typeof key === 'string' && selectableIds.has(key),
              ),
            ),
          getCheckboxProps: (record) => ({
            disabled: busy || !nodeDNSSelectable(record),
            'aria-label': t('nodeDNS.selectFor', { domain: record.name, type: record.type }),
          }),
        }}
        pagination={{
          defaultPageSize: 10,
          showSizeChanger: true,
          pageSizeOptions: [10, 25, 50],
          showTotal: (total) => t('nodeDNS.total', { count: total }),
        }}
        locale={{ emptyText: query.isError ? t('nodeDNS.loadFailed') : t('nodeDNS.empty') }}
      />
      <section className="node-dns-certificates" aria-label={t('nodeDNS.certificateDomains')}>
        <Typography.Text strong>{t('nodeDNS.certificateDomains')}</Typography.Text>
        <Typography.Paragraph type="secondary">{t('nodeDNS.certificateHint')}</Typography.Paragraph>
        <div className="node-dns-selected-domains">
          {domains.map((domain) => (
            <Tag key={domain}>{domain}</Tag>
          ))}
        </div>
        <Space wrap>
          <Typography.Text>
            {t('nodeDNS.selectionCount', {
              records: selectedRecords.length,
              domains: domains.length,
            })}
          </Typography.Text>
        </Space>
        <NodeCertificatePanel
          node={node}
          domains={domains}
          recordIds={selectedRecords.map((record) => record.id)}
          disabled={!writable || !!editor}
        />
      </section>
    </Modal>
  );
}
