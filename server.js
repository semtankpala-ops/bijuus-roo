import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  ssl: isProd
    ? (process.env.DB_SSL === 'false'
        ? false
        : { rejectUnauthorized: true })
    : false
});

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const COOKIE_NAME = 'bijuus_session';
const SESSION_SECRET = process.env.SESSION_SECRET || '';

if (isProd && SESSION_SECRET.length < 32) {
  throw new Error(
    'SESSION_SECRET precisa ter pelo menos 32 caracteres em produção.'
  );
}

app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  cors({
    origin: false,
    credentials: true
  })
);

app.set(
  'trust proxy',
  process.env.TRUST_PROXY === '1' ? 1 : false
);

function sameOrigin(req) {
  const origin = req.headers.origin;

  if (!origin) return true;

  try {
    return new URL(origin).host === req.get('host');
  } catch {
    return false;
  }
}

app.use((req, res, next) => {
  if (
    ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) &&
    ![
      '/api/auth/login',
      '/api/auth/register',
      '/api/auth/password-reset/consume'
    ].includes(req.path) &&
    !sameOrigin(req)
  ) {
    return res
      .status(403)
      .json({ error: 'Origem não autorizada.' });
  }

  next();
});

app.use((req, res, next) => {
  if (
    ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) &&
    req.path !== '/api/auth/login' &&
    req.path !== '/api/auth/register' &&
    !req.headers['content-type']?.startsWith(
      'application/json'
    )
  ) {
    return res.status(415).json({
      error: 'Content-Type precisa ser application/json.'
    });
  }

  next();
});

app.use(express.json({ limit: '2mb' }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 200,
    standardHeaders: true,
    legacyHeaders: false
  })
);

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function signSession(id, exp) {
  return b64url(
    crypto
      .createHmac('sha256', SESSION_SECRET)
      .update(id + '.' + exp)
      .digest()
  );
}

function newSessionToken() {
  const id = crypto.randomUUID();
  const exp = Date.now() + SESSION_TTL_MS;

  return {
    id,
    exp,
    token:
      id +
      '.' +
      exp +
      '.' +
      signSession(id, exp)
  };
}

function parseCookie(req, name) {
  const c = req.headers.cookie || '';

  const m = c
    .split(';')
    .map(s => s.trim())
    .find(s => s.startsWith(name + '='));

  return m
    ? decodeURIComponent(m.slice(name.length + 1))
    : null;
}

async function auth(req, res, next) {
  try {
    const token = parseCookie(req, COOKIE_NAME);

    if (!token) {
      return res
        .status(401)
        .json({ error: 'Não autenticado' });
    }

    const [id, exp, sig] = token.split('.');

    if (
      !id ||
      !exp ||
      !sig ||
      Number(exp) < Date.now() ||
      !crypto.timingSafeEqual(
        Buffer.from(sig),
        Buffer.from(signSession(id, Number(exp)))
      )
    ) {
      return res
        .status(401)
        .json({ error: 'Sessão inválida' });
    }

    const { rows } = await pool.query(
      `
      SELECT
        s.user_id,
        u.username,
        u.email,
        u.cargo,
        u.status_conta,
        p.id AS personagem_id,
        p.nick,
        p.classe,
        p.nivel
      FROM sessoes s
      JOIN usuarios u
        ON u.id = s.user_id
      LEFT JOIN personagens p
        ON p.usuario_id = u.id
      WHERE s.session_id = $1
        AND s.expira_em > now()
      `,
      [id]
    );

    if (
      !rows[0] ||
      rows[0].status_conta !== 'ATIVA'
    ) {
      return res
        .status(401)
        .json({ error: 'Conta inativa' });
    }

    req.user = rows[0];
    req.sessionId = id;

    next();
  } catch (e) {
    console.error(e);

    res
      .status(500)
      .json({ error: 'Erro interno' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (roles.includes(req.user.cargo)) {
      return next();
    }

    return res
      .status(403)
      .json({ error: 'Sem permissão' });
  };
}

function setSessionCookie(res, token) {
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(
      SESSION_TTL_MS / 1000
    )}${isProd ? '; Secure' : ''}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${
      isProd ? '; Secure' : ''
    }`
  );
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);

  const hash = await new Promise(
    (resolve, reject) => {
      crypto.scrypt(
        password,
        salt,
        64,
        {
          N: 16384,
          r: 8,
          p: 1
        },
        (e, d) => (e ? reject(e) : resolve(d))
      );
    }
  );

  return `scrypt$${b64url(salt)}$${b64url(hash)}`;
}

async function verifyPassword(
  password,
  stored
) {
  try {
    const [, saltB, hashB] =
      stored.split('$');

    const salt = Buffer.from(
      saltB,
      'base64url'
    );

    const expected = Buffer.from(
      hashB,
      'base64url'
    );

    const hash = await new Promise(
      (resolve, reject) => {
        crypto.scrypt(
          password,
          salt,
          expected.length,
          {
            N: 16384,
            r: 8,
            p: 1
          },
          (e, d) =>
            e ? reject(e) : resolve(d)
        );
      }
    );

    return crypto.timingSafeEqual(
      hash,
      expected
    );
  } catch {
    return false;
  }
}

app.get(
  '/api/health',
  async (req, res) => {
    try {
      await pool.query('SELECT 1');

      res.json({
        ok: true,
        service: 'bijuus-roo',
        version: '26.0.0'
      });
    } catch {
      res.status(503).json({
        ok: false
      });
    }
  }
);

app.get('/api/config', (req, res) => {
  res.json({
    version: '26.0.0',
    roles: [
      'MEMBRO',
      'LIDER',
      'ADMIN'
    ],
    classes: [
      'Insurgente',
      'Lorde',
      'Paladino',
      'Sumo Sacerdote',
      'Mestre',
      'Arquimago',
      'Professor',
      'Algoz',
      'Desordeiro',
      'Menestrel',
      'Mestre-Ferreiro',
      'Criador',
      'Invocador (Doram)'
    ]
  });
});

app.post(
  '/api/auth/register',
  async (req, res) => {
    try {
      const {
        username,
        email,
        password,
        nick,
        classe,
        nivel = 99
      } = req.body || {};

      if (
        !username ||
        !email ||
        !password ||
        !nick ||
        !classe
      ) {
        return res.status(400).json({
          error:
            'Preencha todos os campos.'
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            'A senha precisa ter pelo menos 8 caracteres.'
        });
      }

      const exists = await pool.query(
        `
        SELECT 1
        FROM usuarios
        WHERE lower(username)=lower($1)
           OR lower(email)=lower($2)
        `,
        [username, email]
      );

      if (exists.rowCount) {
        return res.status(409).json({
          error:
            'Usuário ou e-mail já cadastrado.'
        });
      }

      const passwordHash =
        await hashPassword(password);

      const client =
        await pool.connect();

      try {
        await client.query('BEGIN');

        const u =
          await client.query(
            `
            INSERT INTO usuarios
              (
                username,
                email,
                senha_hash,
                cargo,
                status_conta
              )
            VALUES
              (
                $1,
                $2,
                $3,
                'MEMBRO',
                'PENDENTE'
              )
            RETURNING id
            `,
            [
              username,
              email,
              passwordHash
            ]
          );

        await client.query(
          `
          INSERT INTO personagens
            (
              usuario_id,
              nick,
              classe,
              nivel
            )
          VALUES
            (
              $1,
              $2,
              $3,
              $4
            )
          `,
          [
            u.rows[0].id,
            nick,
            classe,
            Math.max(
              1,
              Math.min(
                99,
                Number(nivel) || 99
              )
            )
          ]
        );

        await client.query('COMMIT');

        res.status(201).json({
          ok: true,
          status: 'PENDENTE'
        });
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível criar a conta.'
      });
    }
  }
);

app.post(
  '/api/auth/login',
  async (req, res) => {
    try {
      const {
        username,
        password
      } = req.body || {};

      if (!username || !password) {
        return res.status(400).json({
          error:
            'Informe usuário e senha.'
        });
      }

      const { rows } =
        await pool.query(
          `
          SELECT
            u.*,
            p.id AS personagem_id,
            p.nick,
            p.classe,
            p.nivel
          FROM usuarios u
          LEFT JOIN personagens p
            ON p.usuario_id=u.id
          WHERE lower(u.username)=lower($1)
          `,
          [username]
        );

      const u = rows[0];

      if (
        !u ||
        !(await verifyPassword(
          password,
          u.senha_hash
        ))
      ) {
        return res.status(401).json({
          error:
            'Usuário ou senha inválidos.'
        });
      }

      if (
        u.status_conta !== 'ATIVA'
      ) {
        return res.status(403).json({
          error:
            u.status_conta === 'PENDENTE'
              ? 'Sua conta está aguardando aprovação da liderança.'
              : 'Sua conta está bloqueada.'
        });
      }

      const s =
        newSessionToken();

      await pool.query(
        `
        INSERT INTO sessoes
          (
            session_id,
            user_id,
            expira_em
          )
        VALUES
          (
            $1,
            $2,
            to_timestamp($3/1000.0)
          )
        `,
        [
          s.id,
          u.id,
          s.exp
        ]
      );

      await pool.query(
        `
        UPDATE usuarios
        SET
          ultimo_login=now(),
          atualizado_em=now()
        WHERE id=$1
        `,
        [u.id]
      );

      setSessionCookie(
        res,
        s.token
      );

      res.json({
        id: u.id,
        username: u.username,
        email: u.email,
        cargo: u.cargo,
        status_conta:
          u.status_conta,
        personagem:
          u.personagem_id
            ? {
                id:
                  u.personagem_id,
                nick: u.nick,
                classe: u.classe,
                nivel: u.nivel
              }
            : null
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error: 'Erro ao entrar.'
      });
    }
  }
);

app.post(
  '/api/auth/logout',
  auth,
  async (req, res) => {
    await pool.query(
      `
      DELETE FROM sessoes
      WHERE session_id=$1
      `,
      [req.sessionId]
    );

    clearSessionCookie(res);

    res.json({
      ok: true
    });
  }
);

app.get(
  '/api/auth/me',
  auth,
  (req, res) => {
    res.json({
      id: req.user.user_id,
      username:
        req.user.username,
      email: req.user.email,
      cargo: req.user.cargo,
      status_conta:
        req.user.status_conta,
      personagem:
        req.user.personagem_id
          ? {
              id:
                req.user.personagem_id,
              nick:
                req.user.nick,
              classe:
                req.user.classe,
              nivel:
                req.user.nivel
            }
          : null
    });
  }
);

app.post(
  '/api/auth/change-password',
  auth,
  async (req, res) => {
    const {
      oldPassword,
      newPassword
    } = req.body || {};

    const { rows } =
      await pool.query(
        `
        SELECT senha_hash
        FROM usuarios
        WHERE id=$1
        `,
        [req.user.user_id]
      );

    if (
      !rows[0] ||
      !(await verifyPassword(
        oldPassword || '',
        rows[0].senha_hash
      ))
    ) {
      return res.status(400).json({
        error:
          'Senha atual incorreta.'
      });
    }

    if (
      !newPassword ||
      newPassword.length < 8
    ) {
      return res.status(400).json({
        error:
          'A nova senha precisa ter pelo menos 8 caracteres.'
      });
    }

    if (
      oldPassword ===
      newPassword
    ) {
      return res.status(400).json({
        error:
          'A nova senha precisa ser diferente da atual.'
      });
    }

    await pool.query(
      `
      UPDATE usuarios
      SET
        senha_hash=$1,
        atualizado_em=now()
      WHERE id=$2
      `,
      [
        await hashPassword(
          newPassword
        ),
        req.user.user_id
      ]
    );

    await pool.query(
      `
      DELETE FROM sessoes
      WHERE user_id=$1
        AND session_id<>$2
      `,
      [
        req.user.user_id,
        req.sessionId
      ]
    );

    res.json({
      ok: true
    });
  }
);

const PROFILES = {
  'DPS Físico': [
    ['DANO_PVP', 25],
    ['Dano x Humanoide', 20],
    ['ATQF', 15],
    ['Bônus de dano JxJ', 10],
    ['Ignorar DEFF', 10],
    ['Dano CRIT%', 7],
    ['CRIT', 5],
    ['PV', 4],
    ['Redução de dano JxJ', 4]
  ],

  'DPS Mágico': [
    ['DANO_PVP', 25],
    ['Dano x Humanoide', 20],
    ['ATQM', 15],
    ['Bônus de dano JxJ', 10],
    ['Ignorar DEFM', 10],
    ['Bônus de dano M', 7],
    ['TC Variável %', 5],
    ['PV', 4],
    ['Redução de dano JxJ', 4]
  ],

  'Suporte de Cura': [
    ['PV', 20],
    ['Redução de dano JxJ', 15],
    ['Redução de Dano x Humanoide', 15],
    ['Efeito de Cura', 15],
    ['Cura Recebida%', 8],
    ['DEFF', 4],
    ['DEFM', 4],
    ['RES CRIT', 7],
    ['DANO_PVP', 3],
    ['ATQM', 3],
    ['Recuperar PM', 3],
    ['Esquiva', 3]
  ],

  'Suporte Ofensivo': [
    ['PV', 18],
    ['ATQF', 15],
    ['Redução de dano JxJ', 13],
    ['Redução de Dano x Humanoide', 12],
    ['Efeito de Cura', 10],
    ['Bônus de dano JxJ', 8],
    ['Cura Recebida%', 6],
    ['VMOV%', 5],
    ['VATQ%', 4],
    ['RES CRIT', 4],
    ['DANO_PVP', 3],
    ['Recuperar PM', 2]
  ],

  'Suporte Utilitário': [
    ['PV', 20],
    ['Redução de dano JxJ', 15],
    ['Redução de Dano x Humanoide', 12],
    ['ATQF', 10],
    ['ATQM', 8],
    ['DANO_PVP', 7],
    ['Bônus de dano JxJ', 7],
    ['DEFF', 4],
    ['DEFM', 3],
    ['RES CRIT', 5],
    ['Cura Recebida%', 4],
    ['Recuperar PM', 3],
    ['Esquiva', 2]
  ],

  'Controle': [
    ['PV', 18],
    ['TC Variável %', 15],
    ['Redução de dano JxJ', 12],
    ['Redução de Dano x Humanoide', 10],
    ['ATQM', 10],
    ['DANO_PVP', 8],
    ['Ignorar DEFM', 6],
    ['Bônus de dano JxJ', 6],
    ['VMOV%', 5],
    ['Cura Recebida%', 4],
    ['RES CRIT', 3],
    ['Recuperar PM', 3]
  ],

  'Suporte Híbrido': [
    ['PV', 18],
    ['DANO_PVP', 12],
    ['Dano x Humanoide', 10],
    ['ATQF', 10],
    ['ATQM', 10],
    ['Redução de dano JxJ', 10],
    ['Redução de Dano x Humanoide', 8],
    ['Bônus de dano JxJ', 6],
    ['Efeito de Cura', 5],
    ['VMOV%', 4],
    ['TC Variável %', 4],
    ['RES CRIT', 3]
  ],

  'Tank-DPS': [
    ['PV Máx%', 25],
    ['Redução de dano JxJ', 15],
    ['Redução de Dano x Humanoide', 12],
    ['DANO_PVP', 10],
    ['ATQF', 8],
    ['DEFF', 4],
    ['DEFM', 4],
    ['Bônus de dano JxJ', 6],
    ['Cura Recebida%', 5],
    ['RES CRIT', 5],
    ['Recuperar PV', 3],
    ['Ignorar DEFF', 3]
  ],

  'Tank': [
    ['PV Máx%', 25],
    ['Redução de dano JxJ', 18],
    ['Redução de Dano x Humanoide', 15],
    ['DEFF', 5],
    ['DEFM', 5],
    ['Redução de Dano F%', 10],
    ['RES CRIT', 7],
    ['Cura Recebida%', 5],
    ['Recuperar PV', 4],
    ['DANO_PVP', 3],
    ['ATQF', 1],
    ['ATQM', 1]
  ]
};

const CLASS_PROFILE = {
  'Insurgente': 'DPS Físico',
  'Lorde': 'DPS Físico',
  'Paladino': 'Tank-DPS',
  'Sumo Sacerdote': 'Suporte de Cura',
  'Mestre': 'DPS Físico',
  'Arquimago': 'DPS Mágico',
  'Professor': 'Controle',
  'Algoz': 'DPS Físico',
  'Desordeiro': 'DPS Físico',
  'Menestrel': 'Suporte Ofensivo',
  'Mestre-Ferreiro': 'DPS Físico',
  'Criador': 'Suporte Utilitário',
  'Invocador (Doram)': 'Suporte Híbrido'
};

function n(v) {
  const x = Number(v);
  return Number.isFinite(x)
    ? x
    : 0;
}

function norm(
  values,
  current
) {
  if (
    current <= 0 ||
    values.length === 0
  ) {
    return 0;
  }

  if (values.length === 1) {
    return 50;
  }

  const a = [...values].sort(
    (x, y) => x - y
  );

  const less =
    a.filter(
      x => x < current
    ).length;

  const equal =
    a.filter(
      x => x === current
    ).length;

  return Math.max(
    0,
    Math.min(
      100,
      20 +
        80 *
          (
            (
              less +
              Math.max(
                0,
                equal - 1
              ) /
                2
            ) /
            (a.length - 1)
          )
    )
  );
}

function calculateIFP(
  status,
  classe,
  cohort
) {
  const profile =
    CLASS_PROFILE[classe] ||
    'DPS Físico';

  const weights =
    PROFILES[profile] ||
    PROFILES['DPS Físico'];

  let score = 0;
  let total = 0;

  const merged = x => ({
    ...(x.status || {}),
    DANO_PVP:
      x.dano_pvp
  });

  for (
    const [key, w]
    of weights
  ) {
    const vals =
      cohort
        .map(
          x =>
            n(
              merged(x)[key]
            )
        )
        .filter(v => v > 0);

    const cur =
      n(status[key]);

    const z =
      norm(vals, cur);

    score += z * w;
    total += w;
  }

  const base =
    total
      ? score / total
      : 0;

  const nm = key =>
    norm(
      cohort
        .map(
          x =>
            n(
              merged(x)[key]
            )
        )
        .filter(
          v => v > 0
        ),
      n(status[key])
    );

  let syn = 0;

  if (
    profile === 'DPS Físico' &&
    nm('CRIT') >= 70 &&
    nm('Dano CRIT%') >= 70
  ) {
    syn += 4;
  }

  if (
    profile === 'DPS Mágico' &&
    nm('ATQM') >= 70 &&
    nm('Bônus de dano M') >= 70
  ) {
    syn += 4;
  }

  if (
    profile.startsWith('Suporte') &&
    nm('PV') >= 70 &&
    nm('Redução de dano JxJ') >= 70
  ) {
    syn += 3;
  }

  if (
    profile === 'Suporte Ofensivo' &&
    nm('ATQF') >= 70 &&
    nm('Efeito de Cura') >= 70
  ) {
    syn += 3;
  }

  if (
    profile === 'Tank-DPS' &&
    nm('PV Máx%') >= 70 &&
    nm('DANO_PVP') >= 70
  ) {
    syn += 4;
  }

  const filled =
    Object.keys(
      status || {}
    ).filter(
      k =>
        status[k] !== '' &&
        status[k] !== null &&
        status[k] !== undefined
    ).length;

  const penalty =
    Math.min(
      5,
      filled < 10
        ? 5 *
          (
            1 -
            filled / 10
          )
        : 0
    );

  return Math.round(
    Math.max(
      0,
      Math.min(
        110,
        base +
          Math.min(
            10,
            syn
          ) -
          penalty
      )
    ) * 10
  ) / 10;
}
app.get(
  '/api/status/me',
  auth,
  async (req, res) => {
    try {
      if (!req.user.personagem_id) {
        return res.json([]);
      }

      const { rows } =
        await pool.query(
          `
          SELECT
            id,
            personagem_id,
            data_registro,
            cp,
            dano_pve,
            dano_pvp,
            status,
            observacao,
            ifp,
            ifp_versao
          FROM status_snapshots
          WHERE personagem_id=$1
          ORDER BY data_registro DESC
          `,
          [req.user.personagem_id]
        );

      res.json(rows);
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível carregar os snapshots.'
      });
    }
  }
);

app.post(
  '/api/status/me',
  auth,
  async (req, res) => {
    try {
      const {
        nick,
        classe,
        nivel = 99,
        cp,
        dano_pve,
        dano_pvp,
        status = {},
        observacao = ''
      } = req.body || {};

      if (
        !nick ||
        !classe ||
        cp === undefined ||
        cp === null
      ) {
        return res.status(400).json({
          error:
            'Nick, classe e CP são obrigatórios.'
        });
      }

      const personagemId =
        req.user.personagem_id;

      if (!personagemId) {
        return res.status(400).json({
          error:
            'Sua conta não possui um personagem cadastrado.'
        });
      }

      const nivelFinal =
        Math.max(
          1,
          Math.min(
            99,
            Number(nivel) || 99
          )
        );

      const cpFinal =
        Number(cp);

      const danoPveFinal =
        Number(dano_pve) || 0;

      const danoPvpFinal =
        Number(dano_pvp) || 0;

      if (
        !Number.isFinite(cpFinal)
      ) {
        return res.status(400).json({
          error:
            'CP inválido.'
        });
      }

      const statusFinal = {
        ...(status &&
        typeof status === 'object'
          ? status
          : {}),
        DANO_PVP:
          danoPvpFinal
      };

      const client =
        await pool.connect();

      try {
        await client.query('BEGIN');

        const personagem =
          await client.query(
            `
            SELECT id
            FROM personagens
            WHERE id=$1
              AND usuario_id=$2
            `,
            [
              personagemId,
              req.user.user_id
            ]
          );

        if (!personagem.rows[0]) {
          throw new Error(
            'Personagem não encontrado para esta conta.'
          );
        }

        await client.query(
          `
          UPDATE personagens
          SET
            nick=$1,
            classe=$2,
            nivel=$3,
            atualizado_em=now()
          WHERE id=$4
            AND usuario_id=$5
          `,
          [
            nick,
            classe,
            nivelFinal,
            personagemId,
            req.user.user_id
          ]
        );

        const r =
          await client.query(
            `
            INSERT INTO status_snapshots
              (
                personagem_id,
                cp,
                dano_pve,
                dano_pvp,
                status,
                observacao,
                ifp,
                ifp_versao
              )
            VALUES
              (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                NULL,
                '2.0'
              )
            RETURNING *
            `,
            [
              personagemId,
              cpFinal,
              danoPveFinal,
              danoPvpFinal,
              statusFinal,
              observacao
            ]
          );

        const cohort =
          await client.query(
            `
            SELECT DISTINCT ON (s.personagem_id)
              COALESCE(
                s.status,
                '{}'::jsonb
              ) AS status,
              COALESCE(
                s.dano_pvp,
                0
              ) AS dano_pvp,
              p.classe
            FROM status_snapshots s
            JOIN personagens p
              ON p.id=s.personagem_id
            JOIN usuarios u
              ON u.id=p.usuario_id
            WHERE u.status_conta='ATIVA'
            ORDER BY
              s.personagem_id,
              s.data_registro DESC
            `
          );

        const ifp =
          calculateIFP(
            statusFinal,
            classe,
            (cohort.rows || []).map(
              x => ({
                status:
                  x.status || {},
                dano_pvp:
                  Number(
                    x.dano_pvp || 0
                  ),
                classe:
                  x.classe
              })
            )
          );

        const updated =
          await client.query(
            `
            UPDATE status_snapshots
            SET
              ifp=$1,
              ifp_versao='2.0'
            WHERE id=$2
            RETURNING *
            `,
            [
              ifp,
              r.rows[0].id
            ]
          );

        await client.query(
          `
          INSERT INTO auditoria
            (
              usuario_id,
              acao,
              alvo,
              detalhes
            )
          VALUES
            (
              $1,
              'STATUS_SNAPSHOT',
              $2,
              $3
            )
          `,
          [
            req.user.user_id,
            String(personagemId),
            JSON.stringify({
              ifp,
              ifp_versao:
                '2.0'
            })
          ]
        );

        await client.query(
          'COMMIT'
        );

        res.status(201).json(
          updated.rows[0]
        );
      } catch (e) {
        await client.query(
          'ROLLBACK'
        );

        console.error(
          'ERRO AO SALVAR STATUS:',
          e
        );

        res.status(500).json({
          error:
            e.message ||
            'Não foi possível salvar o snapshot.'
        });
      } finally {
        client.release();
      }
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          e.message ||
          'Não foi possível salvar o snapshot.'
      });
    }
  }
);

app.get(
  '/api/members',
  auth,
  requireRole('LIDER', 'ADMIN'),
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
          SELECT
            u.id,
            u.username,
            u.email,
            u.cargo,
            u.status_conta,
            u.ultimo_login,
            p.nick,
            p.classe,
            p.nivel,

            (
              SELECT cp
              FROM status_snapshots s
              WHERE s.personagem_id=p.id
              ORDER BY
                s.data_registro DESC
              LIMIT 1
            ) AS cp,

            (
              SELECT ifp
              FROM status_snapshots s
              WHERE s.personagem_id=p.id
              ORDER BY
                s.data_registro DESC
              LIMIT 1
            ) AS ifp

          FROM usuarios u

          LEFT JOIN personagens p
            ON p.usuario_id=u.id

          ORDER BY u.criado_em
          `
        );

      res.json(rows);
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível carregar os membros.'
      });
    }
  }
);

app.post(
  '/api/admin/users/:id/approve',
  auth,
  requireRole('LIDER', 'ADMIN'),
  async (req, res) => {
    try {
      await pool.query(
        `
        UPDATE usuarios
        SET
          status_conta='ATIVA',
          atualizado_em=now()
        WHERE id=$1
        `,
        [req.params.id]
      );

      await pool.query(
        `
        INSERT INTO auditoria
          (
            usuario_id,
            acao,
            alvo
          )
        VALUES
          (
            $1,
            'APROVAR_USUARIO',
            $2
          )
        `,
        [
          req.user.user_id,
          req.params.id
        ]
      );

      res.json({
        ok: true
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível aprovar a conta.'
      });
    }
  }
);

app.post(
  '/api/admin/users/:id/block',
  auth,
  requireRole('LIDER', 'ADMIN'),
  async (req, res) => {
    try {
      await pool.query(
        `
        UPDATE usuarios
        SET
          status_conta='BLOQUEADA',
          atualizado_em=now()
        WHERE id=$1
        `,
        [req.params.id]
      );

      await pool.query(
        `
        DELETE FROM sessoes
        WHERE user_id=$1
        `,
        [req.params.id]
      );

      await pool.query(
        `
        INSERT INTO auditoria
          (
            usuario_id,
            acao,
            alvo
          )
        VALUES
          (
            $1,
            'BLOQUEAR_USUARIO',
            $2
          )
        `,
        [
          req.user.user_id,
          req.params.id
        ]
      );

      res.json({
        ok: true
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível bloquear a conta.'
      });
    }
  }
);

app.post(
  '/api/admin/users/:id/reactivate',
  auth,
  requireRole('LIDER', 'ADMIN'),
  async (req, res) => {
    try {
      await pool.query(
        `
        UPDATE usuarios
        SET
          status_conta='ATIVA',
          atualizado_em=now()
        WHERE id=$1
        `,
        [req.params.id]
      );

      await pool.query(
        `
        INSERT INTO auditoria
          (
            usuario_id,
            acao,
            alvo
          )
        VALUES
          (
            $1,
            'REATIVAR_USUARIO',
            $2
          )
        `,
        [
          req.user.user_id,
          req.params.id
        ]
      );

      res.json({
        ok: true
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível reativar a conta.'
      });
    }
  }
);

app.get(
  '/api/compare/:a/:b',
  auth,
  requireRole('LIDER', 'ADMIN'),
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
          SELECT
            p.id,
            p.nick,
            p.classe,

            COALESCE(
              (
                SELECT row_to_json(s0)
                FROM (
                  SELECT
                    s.id,
                    s.data_registro,
                    s.cp,
                    s.dano_pve,
                    s.dano_pvp,
                    s.status,
                    s.ifp,
                    s.ifp_versao
                  FROM status_snapshots s
                  WHERE s.personagem_id=p.id
                  ORDER BY
                    s.data_registro DESC
                  LIMIT 1
                ) s0
              ),
              '{}'::json
            ) AS snapshot

          FROM personagens p
          JOIN usuarios u
            ON u.id=p.usuario_id

          WHERE p.id IN ($1,$2)
            AND u.status_conta='ATIVA'
          `,
          [
            req.params.a,
            req.params.b
          ]
        );

      res.json(rows);
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível comparar.'
      });
    }
  }
);

app.get(
  '/api/dashboard',
  auth,
  async (req, res) => {
    try {
      const [
        snap,
        counts
      ] = await Promise.all([
        req.user.personagem_id
          ? pool.query(
              `
              SELECT
                cp,
                dano_pve,
                dano_pvp,
                ifp,
                ifp_versao,
                data_registro
              FROM status_snapshots
              WHERE personagem_id=$1
              ORDER BY
                data_registro DESC
              LIMIT 1
              `,
              [
                req.user.personagem_id
              ]
            )
          : { rows: [] },

        pool.query(
          `
          SELECT
            COUNT(*)::int AS total,

            COUNT(*)
              FILTER (
                WHERE status_conta='ATIVA'
              )::int AS ativos,

            COUNT(*)
              FILTER (
                WHERE status_conta='PENDENTE'
              )::int AS pendentes

          FROM usuarios
          `
        )
      ]);

      res.json({
        counts:
          counts.rows[0],
        latest:
          snap.rows[0] || null
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível carregar o dashboard.'
      });
    }
  }
);

app.get(
  '/api/ranking/cp',
  auth,
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
          SELECT
            p.id AS personagem_id,
            p.nick,
            p.classe,
            COALESCE(
              s.cp,
              0
            ) AS cp

          FROM personagens p

          JOIN usuarios u
            ON u.id=p.usuario_id

          LEFT JOIN LATERAL (
            SELECT cp
            FROM status_snapshots
            WHERE personagem_id=p.id
            ORDER BY
              data_registro DESC
            LIMIT 1
          ) s ON true

          WHERE u.status_conta='ATIVA'
            AND p.nick IS NOT NULL

          ORDER BY
            COALESCE(s.cp,0) DESC,
            p.nick ASC
          `
        );

      res.json(
        rows.map(
          (r, i) => ({
            posicao: i + 1,
            personagem_id:
              r.personagem_id,
            nick: r.nick,
            classe: r.classe,
            cp:
              Number(r.cp || 0)
          })
        )
      );
    } catch (e) {
      console.error(
        'ERRO NO RANKING:',
        e
      );

      res.status(500).json({
        error:
          'Não foi possível carregar o ranking.'
      });
    }
  }
);
app.get(
  '/api/medals/me',
  auth,
  async (req, res) => {
    try {
      if (!req.user.personagem_id) {
        return res.json([]);
      }

      const { rows } =
        await pool.query(
          `
          SELECT
            m.id,
            m.nome,
            COALESCE(
              (
                SELECT nivel
                FROM medalha_snapshots ms
                WHERE ms.personagem_id=$1
                  AND ms.medalha_id=m.id
                ORDER BY
                  ms.data_registro DESC
                LIMIT 1
              ),
              0
            )::int AS nivel
          FROM medalha_tipos m
          WHERE m.ativo=true
          ORDER BY m.nome
          `,
          [req.user.personagem_id]
        );

      res.json(rows);
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível carregar as medalhas.'
      });
    }
  }
);

app.post(
  '/api/medals/me',
  auth,
  async (req, res) => {
    if (!req.user.personagem_id) {
      return res.status(400).json({
        error:
          'Personagem não cadastrado.'
      });
    }

    const levels =
      req.body?.levels || {};

    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      for (
        const [nome, valor]
        of Object.entries(levels)
      ) {
        const r =
          await client.query(
            `
            SELECT id
            FROM medalha_tipos
            WHERE nome=$1
              AND ativo=true
            `,
            [nome]
          );

        if (!r.rows[0]) {
          continue;
        }

        const nivel =
          Math.max(
            0,
            Math.min(
              999,
              Number(valor) || 0
            )
          );

        await client.query(
          `
          INSERT INTO medalha_snapshots
            (
              personagem_id,
              medalha_id,
              nivel
            )
          VALUES
            (
              $1,
              $2,
              $3
            )
          `,
          [
            req.user.personagem_id,
            r.rows[0].id,
            nivel
          ]
        );
      }

      await client.query(
        `
        INSERT INTO auditoria
          (
            usuario_id,
            acao,
            alvo
          )
        VALUES
          (
            $1,
            'MEDALHAS_SNAPSHOT',
            $2
          )
        `,
        [
          req.user.user_id,
          String(
            req.user.personagem_id
          )
        ]
      );

      await client.query('COMMIT');

      res.status(201).json({
        ok: true
      });
    } catch (e) {
      await client.query(
        'ROLLBACK'
      );

      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível salvar as medalhas.'
      });
    } finally {
      client.release();
    }
  }
);

app.get(
  '/api/medals/history',
  auth,
  async (req, res) => {
    try {
      if (!req.user.personagem_id) {
        return res.json([]);
      }

      const { rows } =
        await pool.query(
          `
          SELECT
            ms.data_registro,
            m.nome,
            ms.nivel
          FROM medalha_snapshots ms
          JOIN medalha_tipos m
            ON m.id=ms.medalha_id
          WHERE ms.personagem_id=$1
          ORDER BY
            ms.data_registro DESC,
            m.nome
          `,
          [req.user.personagem_id]
        );

      res.json(rows);
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível carregar o histórico de medalhas.'
      });
    }
  }
);

function requireParticipantRole(
  req,
  res,
  next
) {
  return requireRole(
    'LIDER',
    'ADMIN'
  )(req, res, next);
}

function supportKeyForClass(
  classe
) {
  return [
    'Sumo Sacerdote',
    'Menestrel',
    'Criador',
    'Professor',
    'Invocador (Doram)'
  ].includes(classe)
    ? 'SUPORTE:' + classe
    : null;
}

function profileForClass(
  classe
) {
  return (
    CLASS_PROFILE[classe] ||
    'DPS Físico'
  );
}

function buildBalancedTeams(
  players,
  teamCount,
  teamSize
) {
  const teams =
    Array.from(
      {
        length: teamCount
      },
      (_, i) => ({
        name: `Time ${i + 1}`,
        members: [],
        sum: 0,
        supports:
          new Set()
      })
    );

  const ordered =
    [...players].sort(
      (a, b) =>
        Number(b.ifp || 0) -
        Number(a.ifp || 0)
    );

  for (const p of ordered) {
    const candidates =
      teams.filter(
        t =>
          t.members.length <
          teamSize
      );

    candidates.sort(
      (a, b) =>
        a.sum - b.sum ||
        a.members.length -
          b.members.length
    );

    let pick =
      candidates.find(
        t =>
          !p.support_key ||
          !t.supports.has(
            p.support_key
          )
      );

    if (!pick) {
      pick = candidates[0];
    }

    if (!pick) {
      continue;
    }

    pick.members.push(p);
    pick.sum += Number(
      p.ifp || 0
    );

    if (p.support_key) {
      pick.supports.add(
        p.support_key
      );
    }
  }

  return teams;
}

function buildMatchesServer(
  event,
  teams
) {
  const matches = [];
  let num = 1;

  if (
    event.formato ===
    'liga'
  ) {
    for (
      let i = 0;
      i < teams.length;
      i++
    ) {
      for (
        let j = i + 1;
        j < teams.length;
        j++
      ) {
        matches.push({
          round: 'Liga',
          number: num++,
          a: teams[i].id,
          b: teams[j].id
        });
      }
    }
  } else {
    let pool =
      teams.map(
        t => t.id
      );

    let size = 1;

    while (
      size < pool.length
    ) {
      size *= 2;
    }

    while (
      pool.length < size
    ) {
      pool.push(null);
    }

    for (
      let i = 0;
      i < pool.length;
      i += 2
    ) {
      matches.push({
        round: 'Mata-mata',
        number: num++,
        a: pool[i],
        b: pool[i + 1]
      });
    }
  }

  return matches;
}

app.post(
  '/api/pvp/events',
  auth,
  requireParticipantRole,
  async (req, res) => {
    const {
      nome = 'PvP Bijuus',
      format = 'liga',
      times: teamCount,
      tamanho: teamSize = 5,
      premiacao = []
    } = req.body || {};

    const n =
      Math.max(
        1,
        Math.min(
          64,
          Number(teamCount) || 0
        )
      );

    const size =
      Math.max(
        1,
        Math.min(
          20,
          Number(teamSize) || 5
        )
      );

    if (!n) {
      return res.status(400).json({
        error:
          'Informe a quantidade de times.'
      });
    }

    try {
      const participantIds =
        Array.isArray(
          req.body?.participantes
        )
          ? req.body.participantes
              .map(String)
              .filter(Boolean)
          : [];

      const filterSql =
        participantIds.length
          ? `AND p.id = ANY($1::uuid[])`
          : '';

      const params =
        participantIds.length
          ? [participantIds]
          : [];

      const { rows } =
        await pool.query(
          `
          SELECT
            p.id,
            p.nick,
            p.classe,
            p.nivel,
            s.ifp,
            s.id AS snapshot_id,
            s.status,
            s.dano_pvp,
            u.status_conta
          FROM personagens p
          JOIN usuarios u
            ON u.id=p.usuario_id
          JOIN LATERAL (
            SELECT
              id,
              ifp,
              status,
              dano_pvp
            FROM status_snapshots
            WHERE personagem_id=p.id
            ORDER BY
              data_registro DESC
            LIMIT 1
          ) s ON true
          WHERE u.status_conta='ATIVA'
            ${filterSql}
          ORDER BY p.nick
          `,
          params
        );

      if (!rows.length) {
        return res.status(400).json({
          error:
            'Não há participantes válidos com snapshot.'
        });
      }

      if (
        participantIds.length &&
        rows.length !==
          participantIds.length
      ) {
        return res.status(400).json({
          error:
            'Um ou mais participantes não são válidos ou não possuem snapshot.'
        });
      }

      if (
        n > rows.length
      ) {
        return res.status(400).json({
          error:
            'O número de times não pode exceder o número de participantes.'
        });
      }

      if (
        rows.length >
        n * size
      ) {
        return res.status(400).json({
          error:
            'O tamanho preferencial informado não comporta todos os participantes.'
        });
      }

      const players =
        rows.map(x => ({
          ...x,
          ifp:
            Number(
              x.ifp || 0
            ),
          funcao:
            profileForClass(
              x.classe
            ),
          support_key:
            supportKeyForClass(
              x.classe
            )
        }));

      const preview =
        buildBalancedTeams(
          players,
          n,
          size
        );

      const client =
        await pool.connect();

      try {
        await client.query(
          'BEGIN'
        );

        const ev =
          await client.query(
            `
            INSERT INTO pvp_eventos
              (
                nome,
                descricao,
                status,
                ifp_versao,
                premiacao
              )
            VALUES
              (
                $1,
                $2,
                'RASCUNHO',
                '2.0',
                $3
              )
            RETURNING *
            `,
            [
              nome,
              `Formato: ${format}; times: ${n}; tamanho preferencial: ${size}`,
              JSON.stringify(
                premiacao
              )
            ]
          );

        const event =
          ev.rows[0];

        const teams = [];

        for (const m of players) {
          await client.query(
            `
            INSERT INTO pvp_participantes
              (
                evento_id,
                personagem_id,
                ifp_congelado,
                funcao_congelada
              )
            VALUES
              (
                $1,
                $2,
                $3,
                $4
              )
            ON CONFLICT
              (
                evento_id,
                personagem_id
              )
            DO NOTHING
            `,
            [
              event.id,
              m.id,
              m.ifp,
              m.funcao
            ]
          );
        }

        for (
          let i = 0;
          i < preview.length;
          i++
        ) {
          const tr =
            await client.query(
              `
              INSERT INTO pvp_times
                (
                  evento_id,
                  nome,
                  ordem
                )
              VALUES
                (
                  $1,
                  $2,
                  $3
                )
              RETURNING *
              `,
              [
                event.id,
                preview[i].name,
                i + 1
              ]
            );

          const t = {
            ...tr.rows[0],
            members: []
          };

          teams.push(t);

          for (
            const m
            of preview[i].members
          ) {
            await client.query(
              `
              INSERT INTO pvp_time_membros
                (
                  time_id,
                  personagem_id,
                  ifp_congelado,
                  funcao_congelada,
                  suporte_chave
                )
              VALUES
                (
                  $1,
                  $2,
                  $3,
                  $4,
                  $5
                )
              `,
              [
                t.id,
                m.id,
                m.ifp,
                m.funcao,
                m.support_key
              ]
            );

            t.members.push({
              id: m.id,
              nick: m.nick,
              classe: m.classe,
              ifp: m.ifp,
              funcao: m.funcao,
              suporte_chave:
                m.support_key,
              snapshot_id:
                m.snapshot_id
            });
          }
        }

        const inserted =
          buildMatchesServer(
            event,
            teams
          );

        for (
          const m of inserted
        ) {
          await client.query(
            `
            INSERT INTO pvp_partidas
              (
                evento_id,
                rodada,
                numero,
                time_a_id,
                time_b_id
              )
            VALUES
              (
                $1,
                $2,
                $3,
                $4,
                $5
              )
            `,
            [
              event.id,
              m.round,
              m.number,
              m.a,
              m.b
            ]
          );
        }

        await client.query(
          `
          INSERT INTO auditoria
            (
              usuario_id,
              acao,
              alvo,
              detalhes
            )
          VALUES
            (
              $1,
              'PVP_PREVIA',
              $2,
              $3
            )
          `,
          [
            req.user.user_id,
            event.id,
            JSON.stringify({
              teams: n,
              teamSize: size,
              format
            })
          ]
        );

        await client.query(
          'COMMIT'
        );

        res.status(201).json({
          event,
          teams
        });
      } catch (e) {
        await client.query(
          'ROLLBACK'
        );

        throw e;
      } finally {
        client.release();
      }
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível gerar o evento PvP.'
      });
    }
  }
);

app.get(
  '/api/pvp/events/current',
  auth,
  async (req, res) => {
    try {
      const e =
        await pool.query(
          `
          SELECT *
          FROM pvp_eventos
          ORDER BY criado_em DESC
          LIMIT 1
          `
        );

      if (!e.rows[0]) {
        return res.json(null);
      }

      const event =
        e.rows[0];

      const t =
        await pool.query(
          `
          SELECT
            id,
            nome,
            ordem
          FROM pvp_times
          WHERE evento_id=$1
          ORDER BY ordem
          `,
          [event.id]
        );

      for (
        const team
        of t.rows
      ) {
        const m =
          await pool.query(
            `
            SELECT
              tm.personagem_id,
              tm.ifp_congelado,
              tm.funcao_congelada,
              tm.suporte_chave,
              p.nick,
              p.classe,
              tm.id
            FROM pvp_time_membros tm
            JOIN personagens p
              ON p.id=tm.personagem_id
            WHERE tm.time_id=$1
            ORDER BY p.nick
            `,
            [team.id]
          );

        team.members =
          m.rows;
      }

      const matches =
        await pool.query(
          `
          SELECT
            id,
            rodada,
            numero,
            time_a_id,
            time_b_id,
            vencedor_time_id,
            data_partida
          FROM pvp_partidas
          WHERE evento_id=$1
          ORDER BY numero
          `,
          [event.id]
        );

      res.json({
        event,
        teams: t.rows,
        matches:
          matches.rows
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível carregar o PvP.'
      });
    }
  }
);
app.post(
  '/api/pvp/events/:id/confirm',
  auth,
  requireParticipantRole,
  async (req, res) => {
    try {
      const ev =
        await pool.query(
          `
          UPDATE pvp_eventos
          SET status='CONFIRMADO'
          WHERE id=$1
            AND status='RASCUNHO'
          RETURNING *
          `,
          [req.params.id]
        );

      if (!ev.rows[0]) {
        return res.status(409).json({
          error:
            'Evento inexistente ou já confirmado.'
        });
      }

      await pool.query(
        `
        INSERT INTO auditoria
          (
            usuario_id,
            acao,
            alvo
          )
        VALUES
          (
            $1,
            'PVP_CONFIRMAR',
            $2
          )
        `,
        [
          req.user.user_id,
          req.params.id
        ]
      );

      res.json({
        ok: true,
        event: ev.rows[0]
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível confirmar o evento.'
      });
    }
  }
);

app.post(
  '/api/pvp/matches/:id/result',
  auth,
  requireParticipantRole,
  async (req, res) => {
    const {
      vencedor_time_id,
      a_kills = 0,
      b_kills = 0,
      players = {}
    } = req.body || {};

    try {
      const q =
        await pool.query(
          `
          SELECT
            p.*,
            e.status
          FROM pvp_partidas p
          JOIN pvp_eventos e
            ON e.id=p.evento_id
          WHERE p.id=$1
          `,
          [req.params.id]
        );

      if (!q.rows[0]) {
        return res.status(404).json({
          error:
            'Partida não encontrada.'
        });
      }

      const partida =
        q.rows[0];

      if (
        partida.status !==
        'CONFIRMADO'
      ) {
        return res.status(409).json({
          error:
            'A partida só pode receber resultado depois da confirmação do evento.'
        });
      }

      if (
        !vencedor_time_id ||
        ![
          partida.time_a_id,
          partida.time_b_id
        ].includes(
          vencedor_time_id
        )
      ) {
        return res.status(400).json({
          error:
            'O vencedor precisa ser um dos dois times da partida.'
        });
      }

      await pool.query(
        `
        UPDATE pvp_partidas
        SET
          vencedor_time_id=$1,
          data_partida=
            COALESCE(
              data_partida,
              now()
            )
        WHERE id=$2
        `,
        [
          vencedor_time_id,
          req.params.id
        ]
      );

      const validMatch =
        await pool.query(
          `
          SELECT
            time_a_id,
            time_b_id
          FROM pvp_partidas
          WHERE id=$1
          `,
          [partida.id]
        );

      if (!validMatch.rows[0]) {
        return res.status(404).json({
          error:
            'Partida não encontrada.'
        });
      }

      const allowedTeams =
        new Set(
          [
            validMatch.rows[0]
              .time_a_id,
            validMatch.rows[0]
              .time_b_id
          ]
            .filter(Boolean)
            .map(String)
        );

      const seen =
        new Set();

      for (
        const [
          personagemId,
          st
        ] of Object.entries(
          players
        )
      ) {
        if (
          seen.has(
            personagemId
          )
        ) {
          continue;
        }

        seen.add(
          personagemId
        );

        const tm =
          await pool.query(
            `
            SELECT 1
            FROM pvp_time_membros
            WHERE personagem_id=$1
              AND time_id=ANY(
                $2::uuid[]
              )
            LIMIT 1
            `,
            [
              personagemId,
              [
                ...allowedTeams
              ]
            ]
          );

        if (!tm.rows[0]) {
          return res.status(400).json({
            error:
              'Jogador não pertence aos times desta partida.'
          });
        }

        const kills =
          Math.max(
            0,
            Number(
              st.kills
            ) || 0
          );

        const deaths =
          Math.max(
            0,
            Number(
              st.deaths
            ) || 0
          );

        const assists =
          Math.max(
            0,
            Number(
              st.assists
            ) || 0
          );

        const sobrevivencia =
          Boolean(
            st.sobrevivencia
          );

        const idp =
          Math.round(
            (
              kills * 3 +
              assists * 1.5 -
              deaths +
              (
                sobrevivencia
                  ? 1
                  : 0
              ) +
              (
                vencedor_time_id &&
                st.time_id &&
                String(
                  st.time_id
                ) ===
                  String(
                    vencedor_time_id
                  )
                  ? 2
                  : 0
              )
            ) * 10
          ) / 10;

        await pool.query(
          `
          INSERT INTO pvp_desempenho
            (
              partida_id,
              personagem_id,
              resultado,
              kills,
              mortes,
              assists,
              dano,
              sobrevivencia,
              idp,
              mvp
            )
          VALUES
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7,
              $8,
              $9,
              false
            )
          ON CONFLICT
            (
              partida_id,
              personagem_id
            )
          DO UPDATE SET
            resultado=
              EXCLUDED.resultado,
            kills=
              EXCLUDED.kills,
            mortes=
              EXCLUDED.mortes,
            assists=
              EXCLUDED.assists,
            dano=
              EXCLUDED.dano,
            sobrevivencia=
              EXCLUDED.sobrevivencia,
            idp=
              EXCLUDED.idp,
            mvp=false
          `,
          [
            partida.id,
            personagemId,
            String(
              st.time_id
            ) ===
            String(
              vencedor_time_id
            )
              ? 'VITORIA'
              : 'DERROTA',
            kills,
            deaths,
            assists,
            st.dano ??
              null,
            sobrevivencia,
            idp
          ]
        );
      }

      await pool.query(
        `
        UPDATE pvp_desempenho
        SET mvp=false
        WHERE partida_id=$1
        `,
        [partida.id]
      );

      const top =
        await pool.query(
          `
          SELECT id
          FROM pvp_desempenho
          WHERE partida_id=$1
          ORDER BY
            idp DESC NULLS LAST
          LIMIT 1
          `,
          [partida.id]
        );

      if (top.rows[0]) {
        await pool.query(
          `
          UPDATE pvp_desempenho
          SET mvp=true
          WHERE id=$1
          `,
          [top.rows[0].id]
        );
      }

      await pool.query(
        `
        INSERT INTO auditoria
          (
            usuario_id,
            acao,
            alvo
          )
        VALUES
          (
            $1,
            'PVP_RESULTADO',
            $2
          )
        `,
        [
          req.user.user_id,
          req.params.id
        ]
      );

      res.json({
        ok: true
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível salvar o resultado.'
      });
    }
  }
);

app.get(
  '/api/pvp/events/:id/standings',
  auth,
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
          SELECT
            t.id,
            t.nome,
            t.ordem,

            COUNT(
              CASE
                WHEN
                  p.vencedor_time_id=t.id
                THEN 1
              END
            )::int AS vitorias,

            COUNT(
              CASE
                WHEN
                  p.vencedor_time_id IS NOT NULL
                  AND p.vencedor_time_id<>t.id
                  AND (
                    p.time_a_id=t.id
                    OR
                    p.time_b_id=t.id
                  )
                THEN 1
              END
            )::int AS derrotas,

            COUNT(
              CASE
                WHEN
                  p.vencedor_time_id IS NOT NULL
                  AND (
                    p.time_a_id=t.id
                    OR
                    p.time_b_id=t.id
                  )
                THEN 1
              END
            )::int AS jogos,

            COALESCE(
              SUM(
                CASE
                  WHEN
                    p.time_a_id=t.id
                  THEN
                    COALESCE(
                      (
                        SELECT
                          SUM(pd.kills)
                        FROM pvp_desempenho pd
                        JOIN pvp_time_membros tm
                          ON tm.personagem_id=pd.personagem_id
                         AND tm.time_id=t.id
                        WHERE pd.partida_id=p.id
                      ),
                      0
                    )

                  WHEN
                    p.time_b_id=t.id
                  THEN
                    COALESCE(
                      (
                        SELECT
                          SUM(pd.kills)
                        FROM pvp_desempenho pd
                        JOIN pvp_time_membros tm
                          ON tm.personagem_id=pd.personagem_id
                         AND tm.time_id=t.id
                        WHERE pd.partida_id=p.id
                      ),
                      0
                    )

                  ELSE 0
                END
              ),
              0
            )::int AS abates

          FROM pvp_times t

          LEFT JOIN pvp_partidas p
            ON p.time_a_id=t.id
            OR p.time_b_id=t.id

          WHERE t.evento_id=$1

          GROUP BY
            t.id

          ORDER BY
            (
              COUNT(
                CASE
                  WHEN
                    p.vencedor_time_id=t.id
                  THEN 1
                END
              ) * 3
            ) DESC,
            vitorias DESC,
            abates DESC
          `,
          [req.params.id]
        );

      res.json(rows);
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível calcular a classificação.'
      });
    }
  }
);

app.get(
  '/api/pvp/events/:id/player-ranking',
  auth,
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
          SELECT
            p.nick,
            p.classe,

            COUNT(pd.id)::int
              AS jogos,

            COUNT(pd.id)
              FILTER (
                WHERE
                  pd.resultado='VITORIA'
              )::int
              AS vitorias,

            COALESCE(
              SUM(pd.kills),
              0
            )::int
              AS abates,

            COALESCE(
              SUM(pd.mortes),
              0
            )::int
              AS mortes,

            COALESCE(
              SUM(pd.assists),
              0
            )::int
              AS assistencias,

            COUNT(pd.id)
              FILTER (
                WHERE pd.mvp=true
              )::int
              AS mvps,

            COALESCE(
              SUM(pd.idp),
              0
            )::numeric
              AS idp

          FROM pvp_desempenho pd

          JOIN personagens p
            ON p.id=pd.personagem_id

          JOIN pvp_partidas pm
            ON pm.id=pd.partida_id

          WHERE pm.evento_id=$1

          GROUP BY
            p.id,
            p.nick,
            p.classe

          ORDER BY
            idp DESC,
            mvps DESC,
            abates DESC
          `,
          [req.params.id]
        );

      res.json(rows);
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível carregar o ranking PvP.'
      });
    }
  }
);

app.post(
  '/api/admin/users/:id/password-reset',
  auth,
  requireRole('ADMIN'),
  async (req, res) => {
    try {
      const r =
        await pool.query(
          `
          SELECT
            id,
            email
          FROM usuarios
          WHERE id=$1
          `,
          [req.params.id]
        );

      if (!r.rows[0]) {
        return res.status(404).json({
          error:
            'Usuário não encontrado.'
        });
      }

      const raw =
        crypto
          .randomBytes(32)
          .toString(
            'base64url'
          );

      const hash =
        crypto
          .createHash('sha256')
          .update(raw)
          .digest('base64url');

      await pool.query(
        `
        UPDATE recuperacao_senha
        SET usado_em=now()
        WHERE usuario_id=$1
          AND usado_em IS NULL
        `,
        [req.params.id]
      );

      await pool.query(
        `
        INSERT INTO recuperacao_senha
          (
            usuario_id,
            token_hash,
            expira_em
          )
        VALUES
          (
            $1,
            $2,
            now()+interval '30 minutes'
          )
        `,
        [
          req.params.id,
          hash
        ]
      );

      await pool.query(
        `
        DELETE FROM sessoes
        WHERE user_id=$1
        `,
        [req.params.id]
      );

      await pool.query(
        `
        INSERT INTO auditoria
          (
            usuario_id,
            acao,
            alvo
          )
        VALUES
          (
            $1,
            'GERAR_RESET_SENHA',
            $2
          )
        `,
        [
          req.user.user_id,
          req.params.id
        ]
      );

      res.json({
        ok: true,
        token: raw,
        expira_em:
          new Date(
            Date.now() +
            30 * 60 * 1000
          ).toISOString()
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível gerar o reset.'
      });
    }
  }
);

app.post(
  '/api/auth/password-reset/consume',
  async (req, res) => {
    try {
      const {
        token,
        newPassword
      } = req.body || {};

      if (
        !token ||
        !newPassword ||
        newPassword.length < 8
      ) {
        return res.status(400).json({
          error:
            'Token e nova senha são obrigatórios.'
        });
      }

      const hash =
        crypto
          .createHash('sha256')
          .update(token)
          .digest('base64url');

      const q =
        await pool.query(
          `
          SELECT
            id,
            usuario_id
          FROM recuperacao_senha
          WHERE token_hash=$1
            AND usado_em IS NULL
            AND expira_em>now()
          LIMIT 1
          `,
          [hash]
        );

      if (!q.rows[0]) {
        return res.status(400).json({
          error:
            'Token inválido ou expirado.'
        });
      }

      const userId =
        q.rows[0].usuario_id;

      await pool.query(
        `
        BEGIN
        `
      );

      try {
        await pool.query(
          `
          UPDATE usuarios
          SET
            senha_hash=$1,
            atualizado_em=now()
          WHERE id=$2
          `,
          [
            await hashPassword(
              newPassword
            ),
            userId
          ]
        );

        await pool.query(
          `
          UPDATE recuperacao_senha
          SET usado_em=now()
          WHERE id=$1
          `,
          [q.rows[0].id]
        );

        await pool.query(
          `
          DELETE FROM sessoes
          WHERE user_id=$1
          `,
          [userId]
        );

        await pool.query(
          `
          COMMIT
          `
        );
      } catch (e) {
        await pool.query(
          `
          ROLLBACK
          `
        );

        throw e;
      }

      res.json({
        ok: true
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error:
          'Não foi possível redefinir a senha.'
      });
    }
  }
);

app.use(
  express.static(
    path.join(
      __dirname,
      'public'
    )
  )
);

app.use(
  (req, res, next) => {
    if (req.method === 'GET') {
      return res.sendFile(
        path.join(
          __dirname,
          'public',
          'index.html'
        )
      );
    }

    next();
  }
);

app.listen(
  port,
  () =>
    console.log(
      `Bijuus Roo V26 listening on http://localhost:${port}`
    )
);

process.on(
  'SIGTERM',
  async () => {
    await pool.end();
    process.exit(0);
  }
);
