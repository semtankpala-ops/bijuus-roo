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
  window.__compareUsers = [];

  window.renderCompare = async function () {
    const box = document.getElementById('compare');
    if (!box) return;

    if (typeof session === 'undefined' || !session) return;

    if (!['ADMIN', 'LIDER'].includes(session.cargo)) {
      box.innerHTML = '<div class="empty">Acesso restrito.</div>';
      return;
    }

    box.innerHTML =
      '<div class="empty">Carregando personagens...</div>';

    try {
      const rows = await api('/members');

      const users = (rows || []).filter(
        u => u.status_conta === 'ATIVA' && u.nick
      );

      window.__compareUsers = users;

      if (users.length < 2) {
        box.innerHTML =
          '<div class="empty">Cadastre pelo menos dois personagens para comparar.</div>';
        return;
      }

      box.innerHTML =
        '<div class="formgrid">' +
        '<div class="field">' +
        '<label>Personagem A</label>' +
        '<select id="cmpA" onchange="renderCompareTable()">' +
        users.map(u =>
          '<option value="' + esc(u.id) + '">' +
          esc(u.nick) + ' — ' +
          esc(u.classe || '—') +
          '</option>'
        ).join('') +
        '</select>' +
        '</div>' +

        '<div class="field">' +
        '<label>Personagem B</label>' +
        '<select id="cmpB" onchange="renderCompareTable()">' +
        users.map((u, i) =>
          '<option value="' + esc(u.id) + '"' +
          (i === 1 ? ' selected' : '') +
          '>' +
          esc(u.nick) + ' — ' +
          esc(u.classe || '—') +
          '</option>'
        ).join('') +
        '</select>' +
        '</div>' +

        '</div>' +
        '<div id="compareTable" class="section"></div>';

      await window.renderCompareTable();

    } catch (e) {
      box.innerHTML =
        '<div class="empty">Não foi possível carregar os personagens: ' +
        esc(e.message || 'erro desconhecido') +
        '</div>';
    }
  };

  window.renderCompareTable = async function () {
    const table = document.getElementById('compareTable');
    const aId = document.getElementById('cmpA')?.value;
    const bId = document.getElementById('cmpB')?.value;

    if (!table || !aId || !bId) return;

    const users = window.__compareUsers || [];

    const a = users.find(
      u => String(u.id) === String(aId)
    );

    const b = users.find(
      u => String(u.id) === String(bId)
    );

    if (!a || !b) return;

    table.innerHTML =
      '<div class="empty">Carregando snapshots...</div>';

    try {
      const [rowsA, rowsB] = await Promise.all([
        api('/members/' + encodeURIComponent(a.id) + '/status'),
        api('/members/' + encodeURIComponent(b.id) + '/status')
      ]);

      const sa = (rowsA || [])[0] || {};
      const sb = (rowsB || [])[0] || {};

      const keys = [
        ['CP', sa.cp, sb.cp],
        ['Dano PvP', sa.dano_pvp, sb.dano_pvp],
        ['Dano PvE', sa.dano_pve, sb.dano_pve]
      ]
      .concat(
        (typeof COMMON !== 'undefined' ? COMMON : [])
        .map(k => [k, sa.status?.[k], sb.status?.[k]])
      )
      .concat(
        (typeof ADVANCED !== 'undefined' ? ADVANCED : [])
        .map(k => [k, sa.status?.[k], sb.status?.[k]])
      )
      .concat(
        (typeof SPECIAL !== 'undefined' ? SPECIAL : [])
        .map(k => [k, sa.status?.[k], sb.status?.[k]])
      );

      table.innerHTML =
        '<div class="tablewrap"><table>' +
        '<tr>' +
        '<th>Atributo</th>' +
        '<th>' + esc(a.nick) + '</th>' +
        '<th>' + esc(b.nick) + '</th>' +
        '<th>Maior</th>' +
        '</tr>' +

        keys.map(r => {
          const av =
            r[1] == null || r[1] === '' ? null : Number(r[1]);

          const bv =
            r[2] == null || r[2] === '' ? null : Number(r[2]);

          const hasA = Number.isFinite(av);
          const hasB = Number.isFinite(bv);

          let maior = '—';

          if (hasA && hasB && av > bv) {
            maior = '<span class="ok">A</span>';
          } else if (hasA && hasB && bv > av) {
            maior = '<span class="ok">B</span>';
          }

          return '<tr>' +
            '<td>' + esc(r[0]) + '</td>' +
            '<td>' + (hasA ? fmt(av) : '—') + '</td>' +
            '<td>' + (hasB ? fmt(bv) : '—') + '</td>' +
            '<td>' + maior + '</td>' +
            '</tr>';
        }).join('') +

        '</table></div>';

    } catch (e) {
      table.innerHTML =
        '<div class="empty">Não foi possível comparar os personagens: ' +
        esc(e.message || 'erro desconhecido') +
        '</div>';
    }
  };

})();
