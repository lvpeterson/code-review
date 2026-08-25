const express = require('express');
const accounts = require('./accounts');
const app = express();

app.get('/accounts/:accountId/balance', function (req, res) {
  const balance = ledger.getBalance(req.params.accountId);
  res.json({ balance });
});

app.post('/accounts/:accountId/transfer', requireAuth, accounts.transfer);

app.get('/ping', function (req, res) {
  res.send('pong');
});

module.exports = app;
