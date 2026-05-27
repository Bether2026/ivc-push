// api/r2-upload.js — Proxy de subida a Cloudflare R2
// El browser manda la foto aquí, este endpoint la sube a R2 y devuelve la URL pública

var crypto = require('crypto');
var https  = require('https');
var url    = require('url');

var R2_ACCOUNT = '4633f7a5c2873a639eb305058f898659';
var R2_BUCKET  = 'ivcfotos';
var R2_ACCESS  = '39a27306c0a28ec1fdeb952ee0a91253';
var R2_SECRET  = '9c8d4c22013108b10e8f881d7175e3b21e63d79d6796f65856aec4579955fdb9';
var R2_HOST    = R2_ACCOUNT + '.r2.cloudflarestorage.com';
var R2_PUBLIC  = 'https://pub-438b0d51c7a246f38a92859d01cedecd.r2.dev';
var APP_SECRET = 'ivc2024secure';
var ALLOWED    = 'https://ivc-seguridad.vercel.app';

function pad(n) { return String(n).padStart(2, '0'); }

function hmac(key, data, enc) {
  return crypto.createHmac('sha256', key).update(data).digest(enc || 'buffer');
}
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function getAuthHeaders(method, objectKey, contentType, body) {
  var now      = new Date();
  var dateStamp = '' + now.getUTCFullYear() + pad(now.getUTCMonth()+1) + pad(now.getUTCDate());
  var amzDate  = dateStamp + 'T' + pad(now.getUTCHours()) + pad(now.getUTCMinutes()) + pad(now.getUTCSeconds()) + 'Z';
  var region   = 'auto';
  var service  = 's3';
  var scope    = dateStamp + '/' + region + '/' + service + '/aws4_request';

  var payloadHash = sha256(body);

  var canonicalHeaders = 'content-type:' + contentType + '\n'
    + 'host:' + R2_HOST + '\n'
    + 'x-amz-content-sha256:' + payloadHash + '\n'
    + 'x-amz-date:' + amzDate + '\n';

  var signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';

  var canonicalReq = method + '\n'
    + '/' + objectKey + '\n'
    + '\n'
    + canonicalHeaders + '\n'
    + signedHeaders + '\n'
    + payloadHash;

  var strToSign = 'AWS4-HMAC-SHA256\n' + amzDate + '\n' + scope + '\n' + sha256(canonicalReq);

  var kDate    = hmac('AWS4' + R2_SECRET, dateStamp);
  var kRegion  = hmac(kDate, region);
  var kService = hmac(kRegion, service);
  var kSigning = hmac(kService, 'aws4_request');
  var sig      = hmac(kSigning, strToSign, 'hex');

  var auth = 'AWS4-HMAC-SHA256 Credential=' + R2_ACCESS + '/' + scope
    + ', SignedHeaders=' + signedHeaders
    + ', Signature=' + sig;

  return {
    'Authorization': auth,
    'Content-Type': contentType,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
    'Host': R2_HOST
  };
}

// Vercel necesita esto para manejar el body como buffer
module.exports.config = { api: { bodyParser: false } };

module.exports = function(req, res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-IVC-Secret, X-IVC-Filename');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  var secret      = req.headers['x-ivc-secret'];
  var filename    = req.headers['x-ivc-filename'];
  var contentType = req.headers['content-type'] || 'image/jpeg';

  if (secret !== APP_SECRET)  return res.status(403).json({ error: 'Forbidden' });
  if (!filename)              return res.status(400).json({ error: 'Missing X-IVC-Filename' });

  // Leer body como buffer
  var chunks = [];
  req.on('data', function(chunk) { chunks.push(chunk); });
  req.on('end', function() {
    var body = Buffer.concat(chunks);
    console.log('[r2-upload] filename:', filename, '| size:', body.length, '| type:', contentType);

    var headers = getAuthHeaders('PUT', filename, contentType, body);
    headers['Content-Length'] = body.length;

    var options = {
      hostname: R2_HOST,
      path: '/' + filename,
      method: 'PUT',
      headers: headers
    };

    var r2req = https.request(options, function(r2res) {
      var data = '';
      r2res.on('data', function(c) { data += c; });
      r2res.on('end', function() {
        console.log('[r2-upload] R2 status:', r2res.statusCode, data.slice(0,200));
        if (r2res.statusCode === 200) {
          res.status(200).json({ publicUrl: R2_PUBLIC + '/' + filename });
        } else {
          res.status(500).json({ error: 'R2 error ' + r2res.statusCode, detail: data });
        }
      });
    });

    r2req.on('error', function(e) {
      console.error('[r2-upload] Error:', e.message);
      res.status(500).json({ error: e.message });
    });

    r2req.write(body);
    r2req.end();
  });
};
