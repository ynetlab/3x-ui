import { expect, it } from 'vitest';
import { Form } from 'antd';
import { fireEvent, screen } from '@testing-library/react';
import { FormProvider, useForm, useWatch } from 'react-hook-form';

import AnyTLSInboundFields from '@/pages/inbounds/form/protocols/anytls';
import AnyTLSOutboundFields from '@/pages/xray/outbounds/protocols/anytls';
import InboundFormModal from '@/pages/inbounds/form/InboundFormModal';
import { renderWithProviders } from './test-utils';
import { DBInbound } from '@/models/dbinbound';

function InboundHarness() {
  const form = useForm({ defaultValues: { settings: { paddingScheme: ['stop=8'] } } });
  const paddingScheme = useWatch({ control: form.control, name: 'settings.paddingScheme' });
  return (
    <FormProvider {...form}>
      <Form>
        <AnyTLSInboundFields />
        <button
          onClick={() => {
            form.setValue('settings.paddingScheme', []);
          }}
        >
          Clear
        </button>
        <output>{JSON.stringify(paddingScheme)}</output>
      </Form>
    </FormProvider>
  );
}
function OutboundHarness() {
  const form = useForm({
    defaultValues: {
      settings: {
        password: 'test-password',
        email: '',
        level: 0,
        idleSessionCheckInterval: 30,
        idleSessionTimeout: 60,
        minIdleSession: 0,
      },
    },
  });
  const minIdleSession = useWatch({ control: form.control, name: 'settings.minIdleSession' });
  return (
    <FormProvider {...form}>
      <Form>
        <AnyTLSOutboundFields />
        <output>{minIdleSession}</output>
      </Form>
    </FormProvider>
  );
}
it('edits newline-separated padding without losing blank lines while typing', () => {
  renderWithProviders(<InboundHarness />);
  const field = screen.getByRole('textbox');
  fireEvent.change(field, { target: { value: 'stop=8\n0=30-30\n' } });
  expect(screen.getByRole('status').textContent).toBe('["stop=8","0=30-30",""]');
  fireEvent.click(screen.getByText('Clear'));
  expect((field as HTMLTextAreaElement).value).toBe('');
});
it('renders password and all four numeric AnyTLS options', () => {
  renderWithProviders(<OutboundHarness />);
  expect(screen.getAllByRole('spinbutton')).toHaveLength(4);
  fireEvent.change(screen.getAllByRole('spinbutton')[3], { target: { value: '2' } });
  expect(screen.getByRole('status').textContent).toBe('2');
  expect(screen.getByDisplayValue('test-password')).toBeTruthy();
});

it('exposes the protocol settings tab when AnyTLS is selected in the complete inbound modal', () => {
  renderWithProviders(
    <InboundFormModal
      open
      mode="add"
      dbInbound={null}
      dbInbounds={[]}
      availableNodes={[]}
      onSaved={() => {}}
      onClose={() => {}}
    />,
  );
  const select = document.querySelector('.ant-select')!;
  fireEvent.mouseDown(select.querySelector('.ant-select-selector') ?? select);
  fireEvent.click(document.querySelector('.ant-select-item-option[title="anytls"]')!);
  fireEvent.click(screen.getByRole('tab', { name: /^Protocol$/ }));
  expect(screen.getByText('Padding scheme', { exact: true })).toBeTruthy();
});

it('offers the shared fallback card for an AnyTLS TLS inbound', () => {
  renderWithProviders(
    <InboundFormModal
      open
      mode="edit"
      dbInbound={
        new DBInbound({
          id: 1,
          protocol: 'anytls',
          port: 443,
          settings: { clients: [] },
          streamSettings: { network: 'tcp', security: 'tls' },
        })
      }
      dbInbounds={[]}
      availableNodes={[]}
      onSaved={() => {}}
      onClose={() => {}}
    />,
  );
  fireEvent.click(screen.getByRole('tab', { name: /^Protocol$/ }));
  expect(screen.getByText('Fallbacks', { exact: true })).toBeTruthy();
});
