import dotenv from 'dotenv';
import pg from 'pg';
import crypto from 'node:crypto';
dotenv.config();
const {Pool}=pg; const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:false});
const [,,username='admin',email='admin@bijuus.local',password='12345678']=process.argv;
const b64=b=>Buffer.from(b).toString('base64url');
const hash=await new Promise((resolve,reject)=>{const salt=crypto.randomBytes(16);crypto.scrypt(password,salt,64,{N:16384,r:8,p:1},(e,d)=>e?reject(e):resolve(`scrypt$${b64(salt)}$${b64(d)}`))});
try {
  const u = await pool.query(
    `INSERT INTO usuarios(username,email,senha_hash,cargo,status_conta)
     VALUES($1,$2,$3,'ADMIN','ATIVA')
     ON CONFLICT(username) DO UPDATE SET
       senha_hash=EXCLUDED.senha_hash,
       email=EXCLUDED.email,
       cargo='ADMIN',
       status_conta='ATIVA',
       atualizado_em=now()
     RETURNING id`,
    [username,email,hash]
  );

  const adminId = u.rows[0].id;

  const personagem = await pool.query(
    `SELECT id FROM personagens WHERE usuario_id=$1 LIMIT 1`,
    [adminId]
  );

  if (!personagem.rowCount) {
    await pool.query(
      `INSERT INTO personagens(usuario_id,nick,classe,nivel)
       VALUES($1,$2,$3,$4)`,
      [adminId,'ADMIN','Insurgente',99]
    );
  }

  console.log('Admin pronto:', adminId);
} finally {
  await pool.end();
}
