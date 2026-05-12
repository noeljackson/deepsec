export async function proxy(req: { query: { url?: string } }) {
  const target = req.query.url;
  if (!target) {
    return null;
  }
  return fetch(target);
}
