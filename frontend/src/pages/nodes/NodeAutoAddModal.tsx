import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Button,
  Checkbox,
  Collapse,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Space,
  Select,
  Tag,
  Typography,
} from 'antd';
import { ClipboardManager, HttpUtil } from '@/utils';
import { buildPairingCommand, buildSlaveInstallCommand, pairingTerminal } from './pairingCommand';
import type { PairingControlInfo, PairingProfile, PairingStatus } from './pairingCommand';
import type { NodeRecord } from '@/schemas/node';

interface Values {
  name: string;
  masterAddress: string;
  address: string;
  port?: number;
  binary: string;
  releaseTag: string;
  allowPrivateAddress: boolean;
  allowPrivateMaster: boolean;
  domains: string;
  primaryDomain: string;
}

export default function NodeAutoAddModal({
  open,
  mode = 'installed',
  existingNode,
  onOpenChange,
  onCompleted,
}: {
  open: boolean;
  mode?: 'installed' | 'new';
  existingNode?: NodeRecord;
  onOpenChange: (open: boolean) => void;
  onCompleted: () => void;
}) {
  const { t } = useTranslation();
  const newInstall = mode === 'new';
  const migration = !!existingNode;
  const recovery = !!existingNode?.controlRecoveryRequired;
  const tr = (key: string) => t(`pages.nodes.autoAdd.${key}`);
  const [form] = Form.useForm<Values>();
  const domainInput = Form.useWatch('domains', form) ?? '';
  const domainOptions = [
    ...new Set(
      domainInput
        .split(/[\s,，;；]+/)
        .map((value: string) => value.trim().toLowerCase().replace(/\.$/, ''))
        .filter(Boolean),
    ),
  ];
  const [control, setControl] = useState<PairingControlInfo | null>(null);
  const [task, setTask] = useState<PairingStatus | null>(null);
  const [command, setCommand] = useState('');
  const [masterAddress, setMasterAddress] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const completed = useRef('');
  const onCompletedRef = useRef(onCompleted);
  useEffect(() => {
    onCompletedRef.current = onCompleted;
  }, [onCompleted]);

  useEffect(() => {
    if (!open) return;
    const abort = new AbortController();
    void HttpUtil.get<PairingControlInfo>('/panel/api/pairings/control', undefined, {
      silent: true,
      signal: abort.signal,
    }).then((msg) => {
      if (abort.signal.aborted) return;
      if (msg.success && msg.obj) {
        setControl(msg.obj);
        setError('');
      } else {
        setError(
          t(`nodeCertificate.errors.${msg.msg}`, {
            defaultValue: t('pages.nodes.autoAdd.unavailable'),
          }),
        );
      }
    });
    return () => abort.abort();
  }, [open, t]);

  const taskId = task?.id;
  const terminal = task ? pairingTerminal(task.status) : false;
  useEffect(() => {
    if (!open || !taskId || terminal) return;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      const msg = await HttpUtil.get<PairingStatus>(
        `/panel/api/pairings/enrollments/${taskId}`,
        undefined,
        { silent: true, signal: abort.signal },
      );
      if (abort.signal.aborted) return;
      if (msg.success && msg.obj) {
        const status = msg.obj;
        setTask(status);
        setError('');
        if (pairingTerminal(status.status)) {
          setCommand('');
          if (status.status === 'completed' && completed.current !== status.id) {
            completed.current = status.id;
            onCompletedRef.current();
          }
          return;
        }
      } else setError(msg.msg || 'pairing_status_unavailable');
      timer = setTimeout(() => {
        void poll();
      }, 2000);
    };
    void poll();
    return () => {
      abort.abort();
      clearTimeout(timer);
    };
  }, [open, taskId, terminal]);

  const generate = async (values: Values) => {
    setBusy(true);
    setError('');
    const msg = await HttpUtil.post<PairingStatus & { profile: PairingProfile }>(
      '/panel/api/pairings/enrollments',
      {
        name: values.name.trim(),
        masterAddress: values.masterAddress.trim(),
        allowPrivateAddress: values.allowPrivateAddress,
        domains: recovery ? [] : values.domains.split(/[\s,，;；]+/).filter(Boolean),
        primaryDomain: values.primaryDomain,
        ...(existingNode ? { existingNodeId: existingNode.id } : {}),
        ...(recovery ? { recovery: true } : {}),
      },
      { silent: true, timeout: 35_000, headers: { 'Content-Type': 'application/json' } },
    );
    setBusy(false);
    if (!msg.success || !msg.obj) {
      setError(
        t(`nodeCertificate.errors.${msg.msg}`, {
          defaultValue: tr('requestFailed'),
        }),
      );
      return;
    }
    const { profile, ...view } = msg.obj;
    setTask(view);
    setControl({ enabled: true, port: profile.masterPort, peer: profile.master });
    setMasterAddress(profile.masterAddress);
    setCopied(false);
    const request = {
      profile,
      address: (values.address ?? '').trim(),
      port: values.port || 0,
      allowPrivateMaster: values.allowPrivateMaster,
    };
    setCommand(
      newInstall
        ? buildSlaveInstallCommand(values.releaseTag, request)
        : buildPairingCommand(values.binary, request),
    );
  };

  const hostRule = {
    pattern: /^(?:\[[0-9a-fA-F:]+\]|[^\s/:?#@[\]]+|[0-9a-fA-F]*:[0-9a-fA-F:]+)$/,
    message: tr('hostHint'),
  };
  return (
    <Modal
      open={open}
      title={
        recovery
          ? t('controlPki.recover')
          : tr(migration ? 'migrate' : newInstall ? 'newInstall' : 'addSlave')
      }
      width={720}
      footer={null}
      onCancel={() => onOpenChange(false)}
    >
      <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
        <Typography.Paragraph style={{ margin: 0 }}>
          {recovery
            ? t('controlPki.recoveryIntro')
            : tr(migration ? 'migrationIntro' : newInstall ? 'newInstallIntro' : 'intro')}
        </Typography.Paragraph>
        {existingNode && (
          <Alert
            type="info"
            title={t('pages.nodes.autoAdd.existingNode', {
              name: existingNode.name,
              id: existingNode.id,
            })}
            description={recovery ? t('controlPki.recoveryHint') : tr('migrationHint')}
          />
        )}
        {error && <Alert type="error" title={tr('requestFailed')} description={error} />}
        {control && (
          <Descriptions
            size="small"
            column={1}
            bordered
            items={[
              { key: 'port', label: tr('controlPort'), children: control.port },
              {
                key: 'fingerprint',
                label: tr('fingerprint'),
                children: (
                  <Typography.Text copyable style={{ wordBreak: 'break-all' }}>
                    {control.peer.fingerprint}
                  </Typography.Text>
                ),
              },
            ]}
          />
        )}
        {control && (!control.enabled || control.peer.role !== 'master') && (
          <Alert type="warning" title={tr('unavailable')} />
        )}
        {!task && (
          <Form
            form={form}
            layout="vertical"
            onFinish={(values) => {
              void generate(values);
            }}
            disabled={busy}
            initialValues={{
              name: existingNode?.name,
              masterAddress: window.location.hostname.replace(/^\[|\]$/g, ''),
              binary: '/usr/local/x-ui/x-ui',
              releaseTag: 'latest',
              allowPrivateAddress: existingNode?.allowPrivateAddress ?? false,
              allowPrivateMaster: false,
            }}
          >
            <Form.Item
              name="name"
              label={tr('nodeName')}
              rules={[{ required: true, whitespace: true, ...(migration ? {} : { max: 256 }) }]}
            >
              <Input maxLength={migration ? undefined : 256} readOnly={migration} />
            </Form.Item>
            <Form.Item
              name="masterAddress"
              label={tr('masterAddress')}
              extra={tr('hostHint')}
              rules={[{ required: true }, hostRule]}
            >
              <Input />
            </Form.Item>
            {!recovery && (
              <>
                <Form.Item
                  name="domains"
                  label={t('nodeCertificate.pairingDomains')}
                  extra={t('nodeCertificate.pairingDomainsHint')}
                  rules={[
                    { required: true, whitespace: true },
                    {
                      validator: async (_, value: string) => {
                        const names = value?.split(/[\s,，;；]+/).filter(Boolean) ?? [];
                        if (
                          !names.length ||
                          names.length > 100 ||
                          names.some((name) => /[/:?#@]/.test(name))
                        )
                          throw new Error(t('nodeCertificate.invalidDomains'));
                      },
                    },
                  ]}
                >
                  <Input.TextArea autoSize={{ minRows: 2, maxRows: 5 }} />
                </Form.Item>
                <Form.Item
                  name="primaryDomain"
                  label={t('nodeCertificate.primaryDomain')}
                  extra={t('nodeCertificate.pairingPrimaryHint')}
                  dependencies={['domains']}
                  rules={[
                    { required: true },
                    {
                      validator: async (_, value: string) => {
                        if (!domainOptions.includes(value) || value?.startsWith('*.'))
                          throw new Error(t('nodeCertificate.invalidPrimary'));
                      },
                    },
                  ]}
                >
                  <Select
                    options={domainOptions
                      .filter((value) => !value.startsWith('*.'))
                      .map((value) => ({ value, label: value }))}
                  />
                </Form.Item>
              </>
            )}
            {newInstall && (
              <Form.Item
                name="releaseTag"
                label={tr('releaseTag')}
                extra={tr('releaseHint')}
                rules={[
                  { required: true },
                  {
                    pattern: /^(?:latest|dev|dev-latest|v?\d+\.\d+\.\d+(?:[-+.][A-Za-z0-9.-]+)?)$/,
                    message: tr('releaseInvalid'),
                  },
                ]}
              >
                <Input placeholder="latest" />
              </Form.Item>
            )}
            <Collapse
              items={[
                {
                  key: 'advanced',
                  forceRender: true,
                  label: tr('advanced'),
                  children: (
                    <>
                      <Form.Item
                        name="address"
                        label={t('nodeCertificate.bootstrapAddress')}
                        extra={t('nodeCertificate.bootstrapAddressHint')}
                        rules={[hostRule]}
                      >
                        <Input />
                      </Form.Item>
                      <Form.Item name="port" label={tr('slavePort')} extra={tr('slavePortHint')}>
                        <InputNumber min={1} max={65535} precision={0} style={{ width: '100%' }} />
                      </Form.Item>
                      {!newInstall && (
                        <Form.Item
                          name="binary"
                          label={tr('binary')}
                          rules={[
                            { required: true },
                            { pattern: /^\/[^\r\n\0]*$/, message: tr('binaryHint') },
                          ]}
                        >
                          <Input />
                        </Form.Item>
                      )}
                      <Form.Item name="allowPrivateAddress" valuePropName="checked">
                        <Checkbox>{tr('privateSlave')}</Checkbox>
                      </Form.Item>
                      <Form.Item name="allowPrivateMaster" valuePropName="checked">
                        <Checkbox>{tr('privateMaster')}</Checkbox>
                      </Form.Item>
                    </>
                  ),
                },
              ]}
            />
            <Button
              type="primary"
              htmlType="submit"
              loading={busy}
              disabled={!control?.enabled || control.peer.role !== 'master'}
              style={{ marginTop: 16 }}
            >
              {tr(newInstall ? 'generateInstall' : 'generate')}
            </Button>
          </Form>
        )}
        {task && (
          <>
            <Descriptions
              size="small"
              column={1}
              bordered
              items={[
                { key: 'address', label: tr('masterAddress'), children: masterAddress },
                {
                  key: 'status',
                  label: tr('status'),
                  children: (
                    <Tag
                      color={
                        task.status === 'completed' ? 'success' : terminal ? 'error' : 'processing'
                      }
                    >
                      {tr(`states.${task.status}`)}
                    </Tag>
                  ),
                },
                {
                  key: 'domain',
                  label: t('nodeCertificate.primaryDomain'),
                  children: task.primaryDomain || '—',
                },
                ...(task.certificateStatus
                  ? [
                      {
                        key: 'certificate',
                        label: t('nodeCertificate.status'),
                        children: t(`nodeCertificate.states.${task.certificateStatus}`, {
                          defaultValue: task.certificateStatus,
                        }),
                      },
                    ]
                  : []),
                {
                  key: 'expiry',
                  label: tr(task.resumeUntil ? 'resumeUntil' : 'expiresAt'),
                  children: new Date(task.resumeUntil || task.expiresAt).toLocaleString(),
                },
              ]}
            />
            {task.lastError && (
              <Alert
                type="warning"
                title={tr('retrying')}
                description={t(`nodeCertificate.errors.${task.lastError}`, {
                  defaultValue: tr('requestFailed'),
                })}
              />
            )}
            {command && (
              <>
                <Alert
                  type="info"
                  title={tr(newInstall ? 'installRunHint' : 'runHint')}
                  description={tr(newInstall ? 'installCredentialHint' : 'credentialHint')}
                />
                <Input.TextArea
                  aria-label={tr('command')}
                  value={command}
                  readOnly
                  autoSize={{ minRows: 4, maxRows: 8 }}
                  style={{ fontFamily: 'monospace' }}
                />
                <Button
                  onClick={() => {
                    void ClipboardManager.copyText(command).then((ok) => {
                      setCopied(ok);
                      if (!ok) setError(tr('copyFailed'));
                    });
                  }}
                >
                  {tr(copied ? 'copied' : 'copy')}
                </Button>
              </>
            )}
            {task.status === 'completed' && <Alert type="success" title={tr('success')} />}
            {terminal && (!migration || task.status !== 'completed') && (
              <Button
                onClick={() => {
                  setTask(null);
                  setCommand('');
                  setError('');
                  form.resetFields(['name', 'address']);
                }}
              >
                {tr('another')}
              </Button>
            )}
          </>
        )}
      </Space>
    </Modal>
  );
}
