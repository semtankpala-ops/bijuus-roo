CREATE EXTENSION IF NOT EXISTS pgcrypto;
DO $$
BEGIN
  CREATE TYPE user_role AS ENUM ('MEMBRO','LIDER','ADMIN');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;

DO $$
BEGIN
  CREATE TYPE account_status AS ENUM ('PENDENTE','ATIVA','BLOQUEADA');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;
CREATE TABLE IF NOT EXISTS usuarios (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username VARCHAR(40) NOT NULL UNIQUE,
  email VARCHAR(254) NOT NULL UNIQUE,
  senha_hash TEXT NOT NULL,
  cargo user_role NOT NULL DEFAULT 'MEMBRO',
  status_conta account_status NOT NULL DEFAULT 'PENDENTE',
  ultimo_login TIMESTAMPTZ,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS personagens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  usuario_id UUID NOT NULL UNIQUE REFERENCES usuarios(id) ON DELETE RESTRICT,
  nick VARCHAR(40) NOT NULL,
  classe VARCHAR(60) NOT NULL,
  nivel SMALLINT NOT NULL DEFAULT 99 CHECK (nivel BETWEEN 1 AND 99),
  ativo BOOLEAN NOT NULL DEFAULT TRUE,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS status_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  personagem_id UUID NOT NULL REFERENCES personagens(id) ON DELETE RESTRICT,
  data_registro TIMESTAMPTZ NOT NULL DEFAULT now(),
  cp NUMERIC,
  dano_pve NUMERIC,
  dano_pvp NUMERIC,
  status JSONB NOT NULL DEFAULT '{}'::jsonb,
  observacao TEXT,
  ifp NUMERIC,
  ifp_versao VARCHAR(20) NOT NULL DEFAULT '2.0'
);
CREATE INDEX IF NOT EXISTS idx_status_personagem_data ON status_snapshots(personagem_id, data_registro DESC);

CREATE TABLE IF NOT EXISTS medalha_tipos (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nome VARCHAR(80) NOT NULL UNIQUE,
  descricao TEXT,
  ativo BOOLEAN NOT NULL DEFAULT TRUE,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS medalha_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  personagem_id UUID NOT NULL REFERENCES personagens(id) ON DELETE RESTRICT,
  medalha_id UUID NOT NULL REFERENCES medalha_tipos(id) ON DELETE RESTRICT,
  nivel INTEGER NOT NULL DEFAULT 0 CHECK (nivel >= 0),
  data_registro TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_medal_personagem_data ON medalha_snapshots(personagem_id, data_registro DESC);

CREATE TABLE IF NOT EXISTS pvp_eventos (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nome VARCHAR(120) NOT NULL,
  descricao TEXT,
  data_evento TIMESTAMPTZ,
  premiacao JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(20) NOT NULL DEFAULT 'RASCUNHO',
  ifp_versao VARCHAR(20) NOT NULL DEFAULT '2.0',
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pvp_times (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  evento_id UUID NOT NULL REFERENCES pvp_eventos(id) ON DELETE RESTRICT,
  nome VARCHAR(80) NOT NULL,
  ordem INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pvp_participantes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  evento_id UUID NOT NULL REFERENCES pvp_eventos(id) ON DELETE RESTRICT,
  personagem_id UUID NOT NULL REFERENCES personagens(id) ON DELETE RESTRICT,
  ifp_congelado NUMERIC,
  funcao_congelada VARCHAR(80),
  inscrito_em TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(evento_id, personagem_id)
);
CREATE INDEX IF NOT EXISTS idx_pvp_participantes_evento ON pvp_participantes(evento_id);

CREATE TABLE IF NOT EXISTS pvp_time_membros (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  time_id UUID NOT NULL REFERENCES pvp_times(id) ON DELETE RESTRICT,
  personagem_id UUID NOT NULL REFERENCES personagens(id) ON DELETE RESTRICT,
  ifp_congelado NUMERIC,
  funcao_congelada VARCHAR(80),
  suporte_chave VARCHAR(120),
  UNIQUE(time_id, personagem_id)
);

CREATE TABLE IF NOT EXISTS pvp_partidas (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  evento_id UUID NOT NULL REFERENCES pvp_eventos(id) ON DELETE RESTRICT,
  rodada VARCHAR(40) NOT NULL,
  numero INTEGER NOT NULL,
  time_a_id UUID REFERENCES pvp_times(id) ON DELETE RESTRICT,
  time_b_id UUID REFERENCES pvp_times(id) ON DELETE RESTRICT,
  vencedor_time_id UUID REFERENCES pvp_times(id) ON DELETE RESTRICT,
  data_partida TIMESTAMPTZ,
  UNIQUE(evento_id, numero)
);

CREATE TABLE IF NOT EXISTS pvp_desempenho (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  partida_id UUID NOT NULL REFERENCES pvp_partidas(id) ON DELETE RESTRICT,
  personagem_id UUID NOT NULL REFERENCES personagens(id) ON DELETE RESTRICT,
  resultado VARCHAR(10) NOT NULL,
  kills INTEGER NOT NULL DEFAULT 0,
  mortes INTEGER NOT NULL DEFAULT 0,
  assists INTEGER NOT NULL DEFAULT 0,
  dano NUMERIC,
  sobrevivencia BOOLEAN,
  idp NUMERIC,
  mvp BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE(partida_id, personagem_id)
);
CREATE INDEX IF NOT EXISTS idx_pvp_desempenho_personagem ON pvp_desempenho(personagem_id);

CREATE TABLE IF NOT EXISTS sessoes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id TEXT NOT NULL UNIQUE,
  user_id UUID NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  expira_em TIMESTAMPTZ NOT NULL,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessoes_user ON sessoes(user_id);
CREATE INDEX IF NOT EXISTS idx_sessoes_expira ON sessoes(expira_em);

CREATE TABLE IF NOT EXISTS auditoria (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  usuario_id UUID REFERENCES usuarios(id) ON DELETE SET NULL,
  acao VARCHAR(80) NOT NULL,
  alvo VARCHAR(120),
  detalhes JSONB NOT NULL DEFAULT '{}'::jsonb,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);


INSERT INTO medalha_tipos(nome,descricao) VALUES
('Medalha de Bravura',''),('Medalha de Heroísmo',''),('Medalha de Sabedoria',''),('Medalha de Charme',''),('Fúria do Vento',''),('Medalha de Gratidão',''),('Medalha de Lealdade',''),('Medalha da Esperança','')
ON CONFLICT (nome) DO NOTHING;

CREATE TABLE IF NOT EXISTS pvp_premiacoes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  evento_id UUID NOT NULL REFERENCES pvp_eventos(id) ON DELETE RESTRICT,
  posicao INTEGER NOT NULL,
  descricao VARCHAR(200) NOT NULL,
  valor NUMERIC,
  UNIQUE(evento_id, posicao)
);

CREATE TABLE IF NOT EXISTS recuperacao_senha (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  usuario_id UUID NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expira_em TIMESTAMPTZ NOT NULL,
  usado_em TIMESTAMPTZ,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_recuperacao_usuario ON recuperacao_senha(usuario_id);
