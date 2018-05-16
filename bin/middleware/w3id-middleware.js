const debug = require('debug')('bin:middleware:w3id-middleware');
const xml2js = require('xml2js').parseString;
const saml2 = require('saml2-js');
const X509Cert = "-----BEGIN CERTIFICATE-----\n" + process.env.W3ID_CERT + "\n-----END CERTIFICATE-----";

const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

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

// router.use(bodyParser.json());
// router.use(bodyParser.urlencoded({ extended: false }));
// router.use(cookieParser());

bodyParser.json(), bodyParser.urlencoded({ extended: false }), cookieParser(),

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
    
    xml2js(XMLDOC, function (err, result) {
        debug('samlp:Response:',  result['samlp:Response']);
    });

    // debug('XMLDOC:', XMLDOC);

    res.json(req.body);

} );

module.exports = router;

/*module.exports = (req, res, next) => {

    if(req.method === "GET" && req.path === '/__auth'){

    } else if(req.method === "POST" && req.path === '/__auth'){

    } else {

    }

};*/