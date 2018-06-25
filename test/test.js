const generatedSecretCharset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

process.env.NODE_ENV = 'development';
process.env.port = (Math.random() * 10000 | 0) + 5000;
process.env.W3ID_IDP_LOGIN_URL = 'http://example.com';
process.env.W3ID_PARTNER_ID = 'test-w3id-app';
process.env.W3ID_CERT = 'VALID_CERTIFICATE_CONTENT';
process.env.W3ID_SECRET = Array.from(Array(72).keys()).map( index => { return generatedSecretCharset[ ( Math.random() * generatedSecretCharset.length | 0 ) ]; } ).join('');

const debug = require('debug')('test:debug');

const w3id = require(`${__dirname}/../index`);
const app = require('./app');
const http = require('http');
const fetch = require('node-fetch');
const cookieParser = require('cookie-parser');
const server = http.createServer(app);

let serverIsListening = false;

const TEST_USER_ID = 'test_user_id@valid.place';
const TEST_SESSION_ID = 'valid_session_id';
const TEST_EXPIRATION_TIME = Date.now() + (1000 * 60 * 60);
const CURRENT_SESSION_HASH = w3id.generateHashForProperties(TEST_USER_ID, TEST_SESSION_ID, TEST_EXPIRATION_TIME);

server.listen(process.env.port);
server.on('error', function(err){
    debug('TEST SERVER had an error:', err);
});
server.on('listening', function(){
    const addr = server.address();
    const bind = typeof addr === 'string' ? 'pipe ' + addr : 'port ' + addr.port;
    serverIsListening = true;
    debug('TEST SERVER listening on ' + bind);
});

it('Should wait for the test server to be ready before running tests', function () {

    this.timeout(10000);

    let checker;

    return new Promise( (resolve, reject) => {

        checker = setInterval(function(){

            if(serverIsListening){
                clearInterval(checker);
                resolve();
            }

        }, 500);

    });

});

it(`Should make a request to '/' and recieve a 200 status`, function(){

    return fetch(`http://0.0.0.0:${process.env.port}`)
        .then(res => {
            if(res.status === 200){
                return;
            } else {
                throw `Recieved a ${res.status} instead of 200`;
            }
        })
    ;

});

it(`Should try to access a protected route ('/protected') and should be redirected to a login URL`, function(){

    return fetch(`http://0.0.0.0:${process.env.port}/protected`, { redirect: 'manual' })
        .then(res => {
            if(res.status === 302){
                return;
            } else {
                throw `Recieved a ${res.status} instead of an expected 302`;
            }
        })
    ;

});

it('Should try to access /protected with a valid session and recieve a 200', function(){

    return fetch(`http://0.0.0.0:${process.env.port}/protected`, {
            headers : {
                cookie : `w3id_userid=${TEST_USER_ID}; w3id_sessionid=${TEST_SESSION_ID}; w3id_expiration=${TEST_EXPIRATION_TIME}; w3id_hash=${CURRENT_SESSION_HASH}`
            }
        })
        .then(res => {

            if(res.status === 200){
                return;
            } else {
                throw `Session was not validated`;
            }

       })
    ;

});

it('Should try to access /protected with a tampered with session which should then be invalidated.', function(){

    return fetch(`http://0.0.0.0:${process.env.port}/protected`, {
            headers : {
                cookie : `w3id_userid=not_the_real_user@valid.place; w3id_sessionid=${TEST_SESSION_ID}; w3id_expiration=${TEST_EXPIRATION_TIME}; w3id_hash=${CURRENT_SESSION_HASH}`
            },
            redirect: 'manual'
        })
        .then(res => {
            if(res.status === 302){
                return;
            } else {
                throw `Session was not invalidated in the expected way`;
            }
        })
    ;

});

it(`Should clear session cookies and challenge the user to authenticate after the 'w3id_challenge' cookie is set`, function(){

    return fetch(`http://0.0.0.0:${process.env.port}/protected`, {
            headers : {
                cookie : `w3id_userid=${TEST_USER_ID}; w3id_sessionid=${TEST_SESSION_ID}; w3id_expiration=${TEST_EXPIRATION_TIME}; w3id_hash=${CURRENT_SESSION_HASH}; w3id_challenge=1;`
            },
            redirect: 'manual'
        })
        .then(res => {

            const cookies = {};

            res.headers.raw()['set-cookie'].forEach(rawCookie => {
                debug(rawCookie);
                const cookie = rawCookie.split(' ')[0];
                cookies[cookie.split('=')[0]] = cookie.split('=')[1];
            });

            if(res.status === 302 && cookies.w3id_userid === ';' && cookies.w3id_sessionid === ';' && cookies.w3id_expiration === ';' && cookies.w3id_hash === ';'){
                return;
            } else {
                throw `User was not challenged to authenticate after 'w3id_challenge' cookie was set`;
            }
        })

});

it(`Should set a 'w3id_redirect' cookie with the value of the path the user tried to access when there is no existing session`, function(){

    const pathToAccess = `/protected?foo=bar&big=blue`

    return fetch(`http://0.0.0.0:${process.env.port}${pathToAccess}`, { redirect: 'manual' })
        .then(res => {

            const w3id_cookie = res.headers.raw()['set-cookie'][0];
            const cookieValue =  decodeURIComponent(w3id_cookie.split('; ')[0].split('=')[1]);

            if(cookieValue === pathToAccess){
                return;
            } else {
                throw `w3id_redirect cookie value did not match the intended redirect path`;
            }

        })
    ;

});

it(`Should detect that the session is too old, clear the session cookies, and redirect to /__auth`, function(){

    const OUTDATED_SESSION_TIME = Date.now();
    const OUTDATED_SESSION_HASH = w3id.generateHashForProperties(TEST_USER_ID, TEST_SESSION_ID, OUTDATED_SESSION_TIME);

    return fetch(`http://0.0.0.0:${process.env.port}/protected`, {
            headers : {
                cookie : `w3id_userid=${TEST_USER_ID}; w3id_sessionid=${TEST_SESSION_ID}; w3id_expiration=${OUTDATED_SESSION_TIME}; w3id_hash=${OUTDATED_SESSION_HASH};`
            },
            redirect: 'manual'
        })
        .then(res => {

            if(res.status === 302 && res.headers.raw().location[0] === `http://0.0.0.0:${process.env.port}/__auth`){
                return;
            } else {
                throw `Middleware did not detect that session was outdated`;
            }

        })
    ;
    
});