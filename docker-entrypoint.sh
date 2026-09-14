#!/bin/sh
set -eu
node - <<'NODE'
const pg=require('pg');
const fs=require('fs');
const p=new pg.Pool({connectionString:process.env.DATABASE_URL});
(async()=>{
  const sql=fs.readFileSync('/app/schema.sql','utf8');
  await p.query(sql);
  await p.end();
})().catch(async e=>{console.error(e);await p.end().catch(()=>{});process.exit(1)});
NODE
node seed-admin.js "${ADMIN_USER:-admin}" "${ADMIN_EMAIL:-admin@bijuus.local}" "${ADMIN_PASSWORD:-12345678}"
exec node server.js
