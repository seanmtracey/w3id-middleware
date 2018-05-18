const debug = require('debug')('bin:middleware:w3id-middleware');
const xml2js = require('xml2js').parseString;
const saml2 = require('saml2-js');
const X509Cert = "-----BEGIN CERTIFICATE-----\n" + process.env.W3ID_CERT + "\n-----END CERTIFICATE-----";

const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const md5 = require('md5');

const router = require('express').Router();

const SAML_CONFIG = {
    path: '/__auth',
    entryPoint: process.env.W3ID_IDP_LOGIN_URL,
    issuer: process.env.W3ID_PARTNER_ID,
    cert : X509Cert,
};

debug(SAML_CONFIG);

var sp_options = {
    entity_id: process.env.W3ID_PARTNER_ID,
    private_key: X509Cert,
    certificate: X509Cert,
    assert_endpoint: process.env.W3ID_IDP_LOGIN_URL
};

var sp = new saml2.ServiceProvider(sp_options);

var idp_options = {
    sso_login_url: process.env.W3ID_IDP_LOGIN_URL,
    certificates: X509Cert
};

var idp = new saml2.IdentityProvider(idp_options);

const COOKIES_NEEDED_FOR_VALIDATION = ['w3id_userid', 'w3id_sessionid', 'w3id_expiration'];

function generateHashForProperties(userID, sessionID, expiration){

    debug('3:', userID, sessionID, expiration);

    const STR = `${userID}-${sessionID}-${expiration}-${process.env.W3ID_SECRET}`;
    const hash = md5(STR);

    debug('STR:', STR);

    return hash;
}

function validateSession(req, res, next){

    debug('validateSession');
    debug('cookies:', req.cookies);

    const session_hash = req.cookies['w3id_hash'];

    if(!session_hash){
        debug('No hash to evaluate for session. Redirecting to login.');
        res.redirect('/__auth');
    } else {

        const missing_cookies = COOKIES_NEEDED_FOR_VALIDATION.map(cookieRequired => {

                debug('Looking for:', cookieRequired);
                debug('Found: ', req.cookies[cookieRequired]);

                if(!req.cookies[cookieRequired]){
                    return cookieRequired;
                } else {
                    return null;
                }
            })
            .filter(isNullValue => isNullValue !== null)
        ;

        if(missing_cookies.length > 0){
            debug(`Missing cookies required to validate session '${missing_cookies.join(`', '`)}'. Redirecting to login.`);
            res.redirect('/__auth');
        } else {
            
            const generated_hash = generateHashForProperties(  decodeURIComponent( req.cookies['w3id_userid'] ),  decodeURIComponent( req.cookies['w3id_sessionid']),  decodeURIComponent( req.cookies['w3id_expiration'] ) );

            debug(`generated_hash: ${generated_hash} session_hash: ${session_hash} eq?: ${generated_hash === session_hash}`);
            
            if(generated_hash === session_hash){
                next();
            } else {
                res.status(401);
                res.end();
            }


        }

    }

}

router.get('/__auth', (req, res, next) => {

    sp.create_login_request_url(idp, {}, function(err, login_url, request_id) {
        if (err !== null){
            return res.send(500);
        } else {
            debug(login_url);
            res.redirect(login_url);
        }
      });

});

router.post('/__auth', bodyParser.json(), bodyParser.urlencoded({ extended: false }), cookieParser(), (req, res, next) => {

    debug('req.body:', req.body);

    const XMLDOC = new Buffer(req.body.SAMLResponse, 'base64').toString('utf-8');

    req.body.stringedSAML = XMLDOC;
    
    debug('XMLDOC:', XMLDOC);

    xml2js(XMLDOC, function (err, result) {
    
        debug('samlp:Response:',  result['samlp:Response']);

        const userID = result['samlp:Response']['saml:Assertion'][0]['saml:Subject'][0]['saml:NameID'][0]._;
        const sessionID = result['samlp:Response']['saml:Assertion'][0]['saml:AuthnStatement'][0].$.SessionIndex;
        const expiration = result['samlp:Response']['saml:Assertion'][0]['saml:AuthnStatement'][0].$.SessionNotOnOrAfter;

        const propertyHash = generateHashForProperties(userID, sessionID, expiration);

        debug('userID:', userID);
        debug('sessionID:', sessionID);
        debug('expiration:', expiration);
        debug('Setting hash:', propertyHash);

        res.cookie( 'w3id_userid', userID, { httpOnly : false, maxAge : 1000 * 60 * 60 * 24 * 10 } );
        res.cookie( 'w3id_sessionid', sessionID, { httpOnly : false, maxAge : 1000 * 60 * 60 * 24 * 10 } );
        res.cookie( 'w3id_expiration', expiration, { httpOnly : false, maxAge : 1000 * 60 * 60 * 24 * 10 } );
        res.cookie( 'w3id_hash', propertyHash, { httpOnly : false, maxAge : 1000 * 60 * 60 * 24 * 10 } );
        
        res.json(result['samlp:Response']);
    
    });

} );


router.all('*', [ bodyParser.json(), bodyParser.urlencoded({ extended: false }), cookieParser() ], validateSession);

module.exports = router;