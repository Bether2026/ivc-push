// api/r2-sign.js — Genera URLs pre-firmadas para Cloudflare R2

var crypto = require('crypto');

var R2_ACCOUNT = '4633f7a5c2873a639eb305058f898659';
var R2_BUCKET  = 'ivcfotos';
var R2_ACCESS  = '39a27306c0a28ec1fdeb952ee0a91253';
var R2_SECRET  = '9c8d4c22013108b10e8f881d7175e3b21e63d79d6796f65856aec4579955fdb9';
var R2_HOST    = R2_ACCOUNT + '.r2.cloudflarestorage.com';
var R2_PUBLIC  = 'https://pub-438b0d51c7a246f38a92859d01cedecd.r2.dev';
var APP_SECRET = 'ivc2024secure';
var ALLOWED    = 'https://ivc-seguridad.vercel.app';

function sign(key, msg) {
  return crypto.createHmac('sha256', key).update(msg, 'utf8').digest();
}
function signHex(key, msg) {
  return crypto.createHmac('sha256', key).update(msg, 'utf8').digest('hex');
}
function hashHex(msg) {
  return crypto.createHash('sha256').update(msg, 'utf8').digest('hex');
}
function pad(s) { return String(s).padStart(2,'0'); }

module.exports = function(req, res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  var body        = req.body || {};
  var secret      = body.secret;
  var filename    = body.filename;
  var contentType = body.contentType;

  if (secret !== APP_SECRET) return res.status(403).json({ error: 'Forbidden' });
  if (!filename || !contentType) return res.status(400).json({ error: 'Missing params' });

  var allowed = ['image/jpeg','image/jpg','image/png','image/webp','application/pdf'];
  if (allowed.indexOf(contentType) < 0) return res.status(400).json({ error: 'Type not allowed' });

  var now = new Date();
  var Y   = now.getUTCFullYear();
  var M   = pad(now.getUTCMonth() + 1);
  var D   = pad(now.getUTCDate());
  var h   = pad(now.getUTCHours());
  var m   = pad(now.getUTCMinutes());
  var s   = pad(now.getUTCSeconds());

  var dateStamp = '' + Y + M + D;
  var amzDate   = dateStamp + 'T' + h + m + s + 'Z';
  var region    = 'auto';
  var service   = 's3';
  var expires   = 300;
  var credential = R2_ACCESS + '/' + dateStamp + '/' + region + '/' + service + '/aws4_request';

  var qs = 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
    + '&X-Amz-Credential=' + encodeURIComponent(credential)
    + '&X-Amz-Date=' + amzDate
    + '&X-Amz-Expires=' + expires
    + '&X-Amz-SignedHeaders=host';

  var canonicalReq = 'PUT\n/' + filename + '\n' + qs + '\nhost:' + R2_HOST + '\n\nhost\nUNSIGNED-PAYLOAD';

  var scope     = dateStamp + '/' + region + '/' + service + '/aws4_request';
  var strToSign = 'AWS4-HMAC-SHA256\n' + amzDate + '\n' + scope + '\n' + hashHex(canonicalReq);

  var kDate    = sign('AWS4' + R2_SECRET, dateStamp);
  var kRegion  = sign(kDate, region);
  var kService = sign(kRegion, service);
  var kSigning = sign(kService, 'aws4_request');
  var signature = signHex(kSigning, strToSign);

  var uploadUrl = 'https://' + R2_HOST + '/' + filename + '?' + qs + '&X-Amz-Signature=' + signature;
  var publicUrl = R2_PUBLIC + '/' + filename;

  return res.status(200).json({ uploadUrl: uploadUrl, publicUrl: publicUrl });
};
