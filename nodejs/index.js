const fs = require('fs');
const path = require('path');
const express = require('express');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const publicKey = fs.readFileSync(path.resolve('/key/public.pem'));
const privateKey = fs.readFileSync(path.resolve('/key/private.pem'));

const app = express();
app.use(morgan('combined'))
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get('/hello', function (req, res) {
  res.send('Hello World!');
});

app.post('/auth/login', function(req, res) {
  const name = req.body.name;
  const payload = {
    name,
    jti: String(Math.random()),
  }
  const token = jwt.sign(
    payload,
    privateKey,
    {
      algorithm: 'RS256',
      expiresIn: 300,
    }
  );
  res.status(200).json({jwt: token});
});

app.get('/api/me', function(req, res) {
  const auth = req.get('Authorization');
  const authToken = auth.split(' ');
  const token = jwt.verify(authToken[1], publicKey)
  res.status(200).json(token);
});

app.use(function(err, req, res, nex) {
  res.status(500).send(err.message);
});

app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});
