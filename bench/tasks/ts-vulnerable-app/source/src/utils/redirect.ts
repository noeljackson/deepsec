export function loginCallback(req: any, res: any) {
  res.redirect(req.query.next);
}

export function loginCallbackSafe(_req: any, res: any) {
  res.redirect("/dashboard");
}
