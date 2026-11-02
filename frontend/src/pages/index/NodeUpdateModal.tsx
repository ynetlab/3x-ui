import { lazy, useEffect, useState } from 'react';
import { Alert, Modal, Spin } from 'antd';
import { useTranslation } from 'react-i18next';

import { useNodeTarget } from '@/api/nodeTarget';
import { HttpUtil } from '@/utils';
import type { Status } from '@/models/status';
import type { PanelUpdateInfo } from './PanelUpdateModal';

const PanelUpdateModal = lazy(() => import('./PanelUpdateModal'));
const VersionModal = lazy(() => import('./VersionModal'));

interface Props {
  kind: 'panel' | 'version';
  open: boolean;
  name: string;
  status: Status;
  onClose: () => void;
  onBusy: (busy: boolean) => void;
  onUpdated: () => Promise<void>;
}

// Keep the updater mounted after its dialog closes so the selected node's
// update-status poll and result dialogs survive the operation.
export default function NodeUpdateModal({
  kind,
  open,
  name,
  status,
  onClose,
  onBusy,
  onUpdated,
}: Props) {
  const { t } = useTranslation();
  const target = useNodeTarget();
  const [info, setInfo] = useState<PanelUpdateInfo | null>(null);
  const [loading, setLoading] = useState(kind === 'panel');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [tip, setTip] = useState('');
  const [wasOpen, setWasOpen] = useState(open);
  if (open !== wasOpen) {
    setWasOpen(open);
    setLoading(open && kind === 'panel');
    if (open) setError('');
  }

  useEffect(() => {
    if (!open || kind !== 'panel') return;
    let cancelled = false;
    void HttpUtil.get<PanelUpdateInfo>(target.url('/panel/api/server/getPanelUpdateInfo'))
      .then((msg) => {
        if (cancelled) return;
        if (msg?.success && msg.obj) setInfo(msg.obj);
        else setError(msg?.msg || t('error'));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, kind, target, t]);

  const handleBusy = (event: { busy: boolean; tip?: string }) => {
    setBusy(event.busy);
    if (event.tip) setTip(event.tip);
    onBusy(event.busy);
    if (!event.busy && kind === 'version') void onUpdated();
  };

  async function changeChannel(dev: boolean) {
    const result = await HttpUtil.post(target.url('/panel/api/server/setUpdateChannel'), { dev });
    if (!result?.success) return;
    // Keep the switch truthful even if the subsequent release lookup fails.
    setInfo((current) =>
      current ? { ...current, channel: dev ? 'dev' : 'stable', updateAvailable: false } : current,
    );
    const updated = await HttpUtil.get<PanelUpdateInfo>(
      target.url('/panel/api/server/getPanelUpdateInfo'),
    );
    if (updated?.success && updated.obj) setInfo(updated.obj);
  }

  return (
    <>
      {kind === 'panel' && (loading || error || !info) ? (
        <Modal
          open={open}
          title={`${t('pages.index.updatePanel')} · ${name}`}
          footer={null}
          onCancel={onClose}
        >
          {error ? <Alert type="error" showIcon title={error} /> : <Spin />}
        </Modal>
      ) : kind === 'panel' && info ? (
        <PanelUpdateModal
          open={open}
          info={info}
          targetName={name}
          devChannelEnable={info.channel === 'dev'}
          onChannelChange={changeChannel}
          onClose={onClose}
          onBusy={handleBusy}
          onUpdated={onUpdated}
        />
      ) : (
        <VersionModal
          open={open}
          status={status}
          targetName={name}
          onClose={onClose}
          onBusy={handleBusy}
        />
      )}
      <Modal
        open={busy}
        title={name}
        footer={null}
        closable={false}
        maskClosable={false}
        keyboard={false}
      >
        <Spin /> <span>{tip || t('loading')}</span>
      </Modal>
    </>
  );
}
