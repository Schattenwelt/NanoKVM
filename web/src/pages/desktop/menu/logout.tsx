import { Popconfirm, Tooltip } from 'antd';
import { LogOutIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import * as api from '@/api/auth.ts';
import { removeToken } from '@/lib/cookie.ts';

export const Logout = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();

  function logout() {
    api
      .logout()
      .catch(() => {})
      .finally(() => {
        removeToken();
        navigate('/auth/login', { replace: true });
      });
  }

  return (
    <Popconfirm
      placement="bottom"
      title={t('settings.account.logoutDesc')}
      okText={t('settings.account.okBtn')}
      cancelText={t('settings.account.cancelBtn')}
      onConfirm={logout}
    >
      <Tooltip title={t('settings.account.logoutBtn')} placement="bottom" mouseEnterDelay={0.6}>
        <div className="flex h-[30px] w-[30px] cursor-pointer items-center justify-center rounded text-neutral-300 hover:bg-neutral-700/80 hover:text-white">
          <LogOutIcon size={18} />
        </div>
      </Tooltip>
    </Popconfirm>
  );
};
