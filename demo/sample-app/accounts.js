function transfer(req, res) {
  const { toAccountId, amount } = req.body;
  ledger.moveFunds(req.params.accountId, toAccountId, amount);
  res.json({ ok: true });
}

module.exports = { transfer };
