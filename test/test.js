const generatedSecretCharset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

const PORT_NUMBER = (Math.random() * 10000 | 0) + 5000;

process.env.W3ID_IDP_LOGIN_URL = 'http://example.com';
process.env.W3ID_PARTNER_ID = 'test-w3id-app';
process.env.W3ID_CERT = 'VALID_CERTIFICATE';
process.env.W3ID_SECRET = Array.from(Array(72).keys()).map( index => { return generatedSecretCharset[ ( Math.random() * generatedSecretCharset.length | 0 ) ]; } ).join('');

const debug = require('debug')('test:debug');

const app = require('./app');
const http = require('http');
const fetch = require('node-fetch');
const server = http.createServer(app);

server.listen(process.env.port);
server.on('error', function(err){
    debug('TEST SERVER had an error:', err);
});
server.on('listening', function(){
    const addr = server.address();
    const bind = typeof addr === 'string' ? 'pipe ' + addr : 'port ' + addr.port;
    debug('TEST SERVER listening on ' + bind);
});

describe('#save()', function() {
    it('should be fine', function(done) {
        setTimeout(done, 1000);
    });
});

