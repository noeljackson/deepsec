export async function findUser(req: any, pool: any) {
  return pool.query("SELECT * FROM users WHERE id = " + req.query.id);
}

export async function findUserSafe(req: any, pool: any) {
  return pool.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
}
