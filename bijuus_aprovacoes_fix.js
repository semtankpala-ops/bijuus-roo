/* Bijuus Roo - correção da tela Aprovações
 * Busca as contas pendentes diretamente do PostgreSQL.
 */
(function () {
  'use strict';

  let ultimaLista = '';

  async function carregarAprovacoes() {
    const box = document.getElementById('approvals');
    if (!box) return;

    if (typeof session === 'undefined' || !session) return;

    if (!['ADMIN', 'LIDER'].includes(session.cargo)) {
      return;
    }

    try {
      const rows = await api('/members');
      const pendentes = (rows || []).filter(
        u => u.status_conta === 'PENDENTE'
      );

      const assinatura = pendentes
        .map(u => [
          u.id,
          u.username,
          u.email,
          u.nick,
          u.classe
        ].join('|'))
        .join('||');

      if (assinatura === ultimaLista) return;
      ultimaLista = assinatura;

      if (!pendentes.length) {
        box.innerHTML =
          '<div class="empty">Nenhuma conta pendente.</div>';
        return;
      }

      box.innerHTML =
        '<div class="tablewrap">' +
        '<table>' +
        '<tr>' +
        '<th>Usuário</th>' +
        '<th>E-mail</th>' +
        '<th>Nick</th>' +
        '<th>Classe</th>' +
        '<th>Ação</th>' +
        '</tr>' +
        pendentes.map(u =>
          '<tr>' +
          '<td>' + esc(u.username || '') + '</td>' +
          '<td>' + esc(u.email || '') + '</td>' +
          '<td>' + esc(u.nick || '—') + '</td>' +
          '<td>' + esc(u.classe || '—') + '</td>' +
          '<td>' +
          '<button class="btn primary" ' +
          'onclick="window.approveServer(\'' + u.id + '\')">' +
          'Aprovar' +
          '</button> ' +
          '<button class="btn danger" ' +
          'onclick="window.blockServer(\'' + u.id + '\')">' +
          'Bloquear' +
          '</button>' +
          '</td>' +
          '</tr>'
        ).join('') +
        '</table>' +
        '</div>';

    } catch (e) {
      box.innerHTML =
        '<div class="empty">' +
        'Não foi possível carregar as contas pendentes: ' +
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

      ultimaLista = '';
      await carregarAprovacoes();

      if (typeof renderAllAsync === 'function') {
        await renderAllAsync();
      }

    } catch (e) {
      toast(
        e.message || 'Não foi possível aprovar a conta.'
      );
    }
  }

  async function blockServer(id) {
    try {
      await api('/admin/users/' + encodeURIComponent(id) + '/block', {
        method: 'POST',
        body: '{}'
      });

      toast('Conta bloqueada com sucesso.');

      ultimaLista = '';
      await carregarAprovacoes();

      if (typeof renderAllAsync === 'function') {
        await renderAllAsync();
      }

    } catch (e) {
      toast(
        e.message || 'Não foi possível bloquear a conta.'
      );
    }
  }

  window.approveServer = approveServer;
  window.blockServer = blockServer;

  /*
   * Verifica periodicamente:
   * - se o usuário já fez login;
   * - se é ADMIN/LIDER;
   * - se existe conta PENDENTE;
   * - e atualiza a tela.
   */
  setInterval(carregarAprovacoes, 1000);

  carregarAprovacoes();

})();
