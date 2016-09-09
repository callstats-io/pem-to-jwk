var asn = require('asn1.js');
var BN = require('bn.js');
var elliptic = require('elliptic');

var namedCurves = [
    {
        "name": "P-256",
        "OID": [1, 2, 840, 10045, 3, 1, 7],
        "g": elliptic.curves.p256.g

    }
];

var oidToJwkName = function(oid) {
    for (var i = namedCurves.length - 1; i >= 0; i--) {
        if (namedCurves[i].OID.length === oid.length) {
            var equal = true;
            for (var x = namedCurves.length - 1; x >= 0; x--) {
                if (namedCurves[i].OID[x] !== oid[x]) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                return namedCurves[i].name;
            }
        }
    }
    throw "No matching curve";
};

var oidToG = function(oid) {
    for (var i = namedCurves.length - 1; i >= 0; i--) {
        if (namedCurves[i].OID.length === oid.length) {
            var equal = true;
            for (var x = namedCurves.length - 1; x >= 0; x--) {
                if (namedCurves[i].OID[x] !== oid[x]) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                return namedCurves[i].g;
            }
        }
    }
    throw "No matching curve";
};

var Pkcs8EC = asn.define('Pkcs8EC', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('body').seq().obj(
            this.key('type').objid(),
            this.key('namedCurve').objid()
        ),
        this.key('eckeyder').octstr()
    );
});

var OpenSSLECPem = asn.define('OpenSSLECPem', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('key').octstr(),
        this.key('params').implicit(0).seq().obj(
            this.key('namedCurve').objid()
        ),
        this.key('pubKeyContainer').implicit(1).seq().obj(
            this.key('publicKey').bitstr()
        )
    );
});

var ECPK = asn.define('ECPK', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('key').octstr()
    );
});

var base64urlencode = function encode(buffer) {
  return buffer.toString('base64').replace(/\//g, '_')
    .replace(/=/g, '')
    .replace(/\+/g, '-');
};
var generateJwk = function (curve, privateKey, publicKey, callback) {
    var jwk = {"kty":"EC"};
    // Curve
    jwk.crv = oidToJwkName(curve);
    // Private key
    jwk.d = base64urlencode(new Buffer(privateKey, 'hex'));
    if (publicKey.readInt8(0) === 4) {
        // Uncompressed key
        jwk.x = base64urlencode(publicKey.slice(1, 33));
        jwk.y = base64urlencode(publicKey.slice(33, 66));
    } else if (publicKey.readInt8(0) == 2 && publicKey.readInt8(0) == 3) {
        // Compressed key
        callback("Compressed public keys are not supported", jwk);
    }
    callback(null, jwk);
};

var pubFromPrivate = function(private, curveOid) {
    var G = oidToG(curveOid);
    var d;
    if (private instanceof BN) {
        d = private;
    } else {
        d = new BN(private, 16);
    }
    var pubPoint = G.mul(d);
    var x = pubPoint.getX().toBuffer();
    var y = pubPoint.getY().toBuffer();
    var pubkey = new Buffer(x.length+y.length+1);
    pubkey.writeInt8(4);
    x.copy(pubkey, 1, 0);
    y.copy(pubkey, x.length+1, 0);
    return pubkey;
};

var ssleayToJwk = function(pemkey, callback) {
    var decoded = OpenSSLECPem.decode(pemkey, 'pem', { label: 'EC PRIVATE KEY' });
    generateJwk(decoded.params.namedCurve, decoded.key, decoded.pubKeyContainer.publicKey.data, callback);
};

var pkcs8ToJwk = function(pkcskey, callback) {
    var decoded = Pkcs8EC.decode(pkcskey, 'pem', { label: 'PRIVATE KEY' });
    var decodedkey = ECPK.decode(decoded.eckeyder, 'der');
    generateJwk(decoded.body.namedCurve, decodedkey.key, pubFromPrivate(decodedkey.key, decoded.body.namedCurve), console.log);
};

module.exports = {
    ssleayToJwk: ssleayToJwk,
    pkcs8ToJwk: pkcs8ToJwk,
    pubFromPrivate: pubFromPrivate,
    generateJwk: generateJwk
};

// var decoded8 = Pkcs8EC.decode(pkcs8key, 'pem', { label: 'PRIVATE KEY' });
// var decoded8key = ECPK.decode(decoded8.eckeyder, 'der');
// var decoded0 = OpenSSLECPem.decode(opensslkey, 'pem', { label: 'EC PRIVATE KEY' });
// //var decodedPem = OpenSSLECPem.decode(pemkey, 'pem', { label: 'EC PRIVATE KEY' });
// console.log(decoded8)
// console.log(decoded8key)
// console.log(decoded0)
// var d = new BN(decoded8key.key, 16);
// var G = oidToG(decoded8.body.namedCurve);
// var pubPoint = G.mul(d);
// var pubkey = decoded0.pubKeyContainer.publicKey.data;
// console.log(pubkey.slice(1, 33));
// console.log(pubkey.slice(33, 65));
// console.log("********");
// console.log(pubPoint);
// var x = pubPoint.getX().toBuffer();
// console.log(x);
// var y = pubPoint.getY().toBuffer();
// console.log(y);
// console.log("********");
// module.exports = {x: pubPoint};


// generateJwk(decoded0.params.namedCurve, decoded0.key, decoded0.pubKeyContainer.publicKey.data, console.log);
// var pubkey = new Buffer(x.length+y.length+1);
// pubkey.writeInt8(4);
// x.copy(pubkey, 1, 0);
// console.log(y.copy(pubkey, x.length+1, 0));
// console.log(pubkey);
// generateJwk(decoded8.body.namedCurve, decoded8key.key, pubkey, console.log);
