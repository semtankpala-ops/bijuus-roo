/* Bijuus Roo - correção da tela Aprovações
 * Usa a API PostgreSQL do servidor.
 */
(function () {
  'use strict';

  async function loadApprovalsFromServer() {
    const box = document.getElementById('approvals');
    if (!box) return;

    if (typeof session === 'undefined' || !session) return;
    if (!['ADMIN', 'LIDER'].includes(session.cargo)) return;

    try {
      const rows = await api('/members');
      const pending = (rows || []).filter(u => u.status_conta === 'PENDENTE');

      if (!pending.length) {
        box.innerHTML = '<div class="empty">Nenhuma conta pendente.</div>';
        return;
      }

      box.innerHTML =
        '<div class="tablewrap"><table>' +
        '<tr><th>Usuário</th><th>E-mail</th><th>Nick</th><th>Classe</th><th>Ação</th></tr>' +
        pending.map(u =>
          '<tr>' +
          '<td>' + esc(u.username || '') + '</td>' +
          '<td>' + esc(u.email || '') + '</td>' +
          '<td>' + esc(u.nick || '—') + '</td>' +
          '<td>' + esc(u.classe || '—') + '</td>' +
          '<td>' +
          '<button class="btn primary" onclick="approveServer(\'' + u.id + '\')">Aprovar</button> ' +
          '<button class="btn danger" onclick="blockServer(\'' + u.id + '\')">Bloquear</button>' +
          '</td>' +
          '</tr>'
        ).join('') +
        '</table></div>';
    } catch (e) {
      box.innerHTML =
        '<div class="empty">Não foi possível carregar as contas pendentes: ' +
        esc(e.message || 'erro desconhecido') +
        '</div>';
    }
  }

  async function approveServer(id) {
    try {
      await api('/admin/users/' + encodeURIComponent(id) + '/approve', {
        method: 'POST',
        body: '{}'
      });

      toast('Conta aprovada com sucesso.');
      await loadApprovalsFromServer();

      if (typeof renderAllAsync === 'function') {
        await renderAllAsync();
      }
    } catch (e) {
      toast(e.message || 'Não foi possível aprovar a conta.');
    }
  }

  async function blockServer(id) {
    try {
      await api('/admin/users/' + encodeURIComponent(id) + '/block', {
        method: 'POST',
        body: '{}'
      });

      toast('Conta bloqueada com sucesso.');
      await loadApprovalsFromServer();

      if (typeof renderAllAsync === 'function') {
        await renderAllAsync();
      }
    } catch (e) {
      toast(e.message || 'Não foi possível bloquear a conta.');
    }
  }

  window.approveServer = approveServer;
  window.blockServer = blockServer;

  const originalRenderApprovals = window.renderApprovals;

  window.renderApprovals = function () {
    loadApprovalsFromServer();

    if (typeof originalRenderApprovals === 'function') {
      try {
        originalRenderApprovals.apply(this, arguments);
      } catch (_) {}
    }
  };

  const originalOpenPage = window.openPage;

  if (typeof originalOpenPage === 'function') {
    window.openPage = function (id) {
      originalOpenPage.apply(this, arguments);

      if (id === 'aprovacoes') {
        setTimeout(loadApprovalsFromServer, 150);
      }
    };
  }

  function boot() {
    setTimeout(loadApprovalsFromServer, 500);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }
})();
