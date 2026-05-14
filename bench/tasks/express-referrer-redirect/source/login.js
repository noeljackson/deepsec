function loginVulnerable(req, res) {
  res.redirect(req.get('Referrer') || '/');
}

function updateVulnerable(req, res) {
  res.redirect(req.headers['referer']);
}

function loginSafe(req, res) {
  const target = req.get('Referrer') || '/';
  if (!/^https?:\/\/(www\.)?example\.com(\/|$)/.test(target)) {
    return res.redirect('/');
  }
  res.redirect(target);
}

module.exports = { loginVulnerable, updateVulnerable, loginSafe };
