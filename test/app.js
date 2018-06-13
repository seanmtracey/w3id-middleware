
const debug = require('debug')('test:server');
const port = process.env.PORT || '3000';
const http = require('http');

const express = require('express');
const app = express();

const w3id = require(`${__dirname}/../index`);

app.set('port', port);

app.get('/logout', (req, res, next) => {

    const oneWeekInMilliseconds = 604800000;
  
    res.cookie( 'w3id_challenge', 1, { httpOnly : false, maxAge : oneWeekInMilliseconds } );
    console.log('VARS:', res.cookies, process.env.NODE_ENV);
    res.end();
  
});
  
app.get('/', (req, res, next) => {
  
    res.end();
  
});
  
app.use(w3id);
  
app.get('/protected',function(req, res, next) {
    res.end();
});

module.exports = app;