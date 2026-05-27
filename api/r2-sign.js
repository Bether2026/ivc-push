// api/r2-sign.js — Genera URLs pre-firmadas para Cloudflare R2
// Usa firma AWS4 manual compatible con R2 (sin dependencias extra)

var crypto = require('crypto');

var R2_ACCOUNT = '4633f7a5c2873a639eb305058f898659';
var R2_BUCKET  = 'ivcfotos';
var R2_ACCESS  = 'ee6e0c112948faad6b8617b797cc29e4';
var R2_SECRET  = '067887f8230bfdfd1d1f028caf71f2686149fac63d454db3a3dd5dfd37f30d46';
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

  var body       = req.body || {};
  var secret      = body.secret;
  var filename    = body.filename;
  var contentType = body.contentType;

  if (secret !== APP_SECRET) return res.status(403).json({ error: 'Forbidden' });
  if (!filename || !contentType) return res.status(400).json({ error: 'Missing params' });

  var allowed = ['image/jpeg','image/jpg','image/png','image/webp','application/pdf'];
  if (allowed.indexOf(contentType) < 0) return res.status(400).json({ error: 'Type not allowed' });

  // Tiempo en UTC — clave para que la firma sea válida
  var now = new Date();
  var Y   = now.getUTCFullYear();
  var M   = pad(now.getUTCMonth() + 1);
  var D   = pad(now.getUTCDate());
  var h   = pad(now.getUTCHours());
  var m   = pad(now.getUTCMinutes());
  var s   = pad(now.getUTCSeconds());

  var dateStamp  = '' + Y + M + D;                        // 20260527
  var amzDate    = dateStamp + 'T' + h + m + s + 'Z';    // 20260527T143022Z
  var region     = 'auto';
  var service    = 's3';
  var expires    = 300; // 5 minutos
  var objectKey  = filename;
  var credential = R2_ACCESS + '/' + dateStamp + '/' + region + '/' + service + '/aws4_request';

  // Query string — DEBE estar ordenado alfabéticamente
  var qs = 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
    + '&X-Amz-Credential=' + encodeURIComponent(credential)
    + '&X-Amz-Date=' + amzDate
    + '&X-Amz-Expires=' + expires
    + '&X-Amz-SignedHeaders=host';

  // Canonical request
  var canonicalHeaders = 'host:' + R2_HOST + '\n';
  var canonicalReq = [
    'PUT',
    '/' + objectKey,
    qs,
    canonicalHeaders,
    'host',
    'UNSIGNED-PAYLOAD'
  ].join('\n');

  // String to sign
  var scope      = dateStamp + '/' + region + '/' + service + '/aws4_request';
  var strToSign  = 'AWS4-HMAC-SHA256\n' + amzDate + '\n' + scope + '\n' + hashHex(canonicalReq);

  // Signing key
  var kDate    = sign('AWS4' + R2_SECRET, dateStamp);
  var kRegion  = sign(kDate, region);
  var kService = sign(kRegion, service);
  var kSigning = sign(kService, 'aws4_request');
  var signature = signHex(kSigning, strToSign);

  var uploadUrl = 'https://' + R2_HOST + '/' + objectKey + '?' + qs + '&X-Amz-Signature=' + signature;
  var publicUrl = R2_PUBLIC + '/' + objectKey;

  console.log('[r2-sign] filename:', filename, '| date:', amzDate);

  return res.status(200).json({ uploadUrl: uploadUrl, publicUrl: publicUrl });
};
