#! /usr/bin/env node
var pemToJwk = require('./index.js');
var content = '';
process.stdin.on('data', function(buf) { content += buf.toString(); });
process.stdin.on('end', function() {
    var converters = [pemToJwk.ssleayToJwk, pemToJwk.pkcs8ToJwk];
    var cb = function (err, jwk) {
        if (err) {
            console.error(err);
            return;
        }
        console.log(jwk);
    };
    for (var i = converters.length - 1; i >= 0; i--) {
        try {
            converters[i](content, cb);
            return;
        } catch (ignore) {

        }
    }
    console.error("Couldn't encode to JWK");
});
process.stdin.resume();
