const debug = require('debug')('bin:middleware:w3id-middleware');

module.exports = (req, res, next) => {
    debug('Request passed through w3id-middleware');
    next();
};