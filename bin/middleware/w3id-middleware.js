const debug = require('debug')('bin:middleware:w3id-middleware');
const passport = require('passport')
const SAML = require('passport-saml');
const xmldom = require('xmldom');
const xpath = require('xpath');
const X509Cert = "-----BEGIN CERTIFICATE-----\n" + process.env.W3ID_CERT + "\n-----END CERTIFICATE-----";
const router = require('express').Router();

const SAML_CONFIG = {
    path: '/__auth',
    entryPoint: process.env.W3ID_IDP_LOGIN_URL,
    issuer: process.env.W3ID_PARTNER_ID,
    cert : X509Cert,
};

debug(SAML);

function patchSAMLRequest(req, res, next) {
    try {
        const xmlData = new Buffer(req.body.SAMLResponse, 'base64').toString('utf-8');

        // Parse XML into DOM
        const doc = new xmldom.DOMParser().parseFromString(xmlData);
        const signedInfos = xpath.select('//*[local-name()=\'SignedInfo\']', doc);
        const assertions = xpath.select('//*[local-name()=\'Assertion\']', doc);

        signedInfos.forEach((signedInfo) => {
            signedInfo.setAttribute(
                'xmlns:ds',
                'http://www.w3.org/2000/09/xmldsig#'
            );
        });

        assertions.forEach((assertion) => {
            assertion.setAttribute(
                'xmlns:saml',
                'urn:oasis:names:tc:SAML:2.0:assertion'
            );
            assertion.setAttribute(
                'xmlns:xs',
                'http://www.w3.org/2001/XMLSchema'
            );
            assertion.setAttribute(
                'xmlns:xsi',
                'http://www.w3.org/2001/XMLSchema-instance'
            );
        });

        req.body.SAMLResponse = new Buffer(doc.toString(), 'utf-8').toString('base64');
        next();
    } catch (error) {
        // Presuming bad SAMLResponse just pass it through
        next(error);
        return;
    }
}


function verifyUser(user, done) {
    done(null, user);
}

function serializeUser(user, done) {
    done(null, user.uid);
}

function deserializeUser(userId, done) {
    const user = User.findById(userId);

    if (!user) {
        done(new Error(`User with id ${userId} not found`), false);
        return;
    }

    done(null, user);

}

// Add SAML strategy to passport.
passport.use(new SAML.Strategy(SAML_CONFIG, verifyUser));
debug('SAML %s Authentication Enabled');

debug('passport:', passport);

// passport.serializeUser(serializeUser);
// passport.deserializeUser(deserializeUser);

router.get('/__auth', passport.authenticate('saml'));
router.post('/__auth', patchSAMLRequest, passport.authenticate('saml', { successRedirect: '/', failureRedirect: '/__auth_fail' }));

router.get('/__auth_fail', (req, res, next) => {
    debug('/__auth_fail:', req);
    res.send('FAILED TO AUTHENTICATE');
});

module.exports = (req, res, next) => {
    debug('Request passed through w3id-middleware');

    if (req.isAuthenticated()) {
        next();
        return;
    } else {
        res.redirect('/__auth_fail');
    }

};