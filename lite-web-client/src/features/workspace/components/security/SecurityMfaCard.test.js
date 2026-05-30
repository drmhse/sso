import { nextTick } from 'vue';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import SecurityMfaCard from './SecurityMfaCard.vue';

const backupCodes = ['ABCD-1234', 'WXYZ-9876'];
const originalClipboard = navigator.clipboard;

afterEach(() => {
  vi.restoreAllMocks();
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: originalClipboard,
  });
  document.body.innerHTML = '';
});

describe('SecurityMfaCard', () => {
  it('copies visible backup codes', async () => {
    const writeText = vi.fn().mockResolvedValue();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });

    const wrapper = mount(SecurityMfaCard, {
      props: {
        mfaStatus: { enabled: true, has_backup_codes: true },
        backupCodes,
      },
    });

    const copyButton = wrapper.findAll('button').find((button) => button.text().includes('Copy Codes'));
    await copyButton.trigger('click');
    await nextTick();

    expect(writeText).toHaveBeenCalledTimes(1);
    expect(writeText.mock.calls[0][0]).toContain('ABCD-1234');
    expect(writeText.mock.calls[0][0]).toContain('WXYZ-9876');
    expect(wrapper.text()).toContain('Copied');
  });

  it('downloads visible backup codes as a text file', async () => {
    const objectUrl = 'blob:authos-backup-codes';
    vi.spyOn(URL, 'createObjectURL').mockReturnValue(objectUrl);
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    const wrapper = mount(SecurityMfaCard, {
      props: {
        mfaStatus: { enabled: true, has_backup_codes: true },
        backupCodes,
      },
      attachTo: document.body,
    });

    const downloadButton = wrapper.findAll('button').find((button) => button.text().includes('Download .txt'));
    await downloadButton.trigger('click');

    expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(click).toHaveBeenCalledTimes(1);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith(objectUrl);
  });
});
