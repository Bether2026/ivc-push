// api/r2-sign.js — Genera URLs pre-firmadas para subida directa a Cloudflare R2
// No requiere dependencias externas — usa crypto nativo de Node.js

var crypto = require('crypto');

var R2_ACCOUNT = '4633f7a5c2873a639eb305058f898659';
var R2_BUCKET  = 'ivcfotos';
var R2_ACCESS  = 'ee6e0c112948faad6b8617b797cc29e4';
var R2_SECRET  = '067887f8230bfdfd1d1f028caf71f2686149fac63d454db3a3dd5dfd37f30d46';
var R2_HOST    = R2_ACCOUNT + '.r2.cloudflarestorage.com';
var APP_SECRET = 'ivc2024secure'; // mismo secret que usa push.js
var ALLOWED_ORIGIN = 'https://ivc-seguridad.vercel.app';

function hmacSha256(key, data, encoding) {
  return crypto.createHmac('sha256', key).update(data).digest(encoding || 'buffer');
}
function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = function(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  var body = req.body || {};
  var secret      = body.secret;
  var filename    = body.filename;      // ej: "novedades/abc123_1234567890.jpg"
  var contentType = body.contentType;  // ej: "image/jpeg"

  // Validaciones
  if (secret !== APP_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (!filename || !contentType) {
    return res.status(400).json({ error: 'Missing filename or contentType' });
  }
  // Solo permitir imágenes y PDF
  var allowed = ['image/jpeg','image/jpg','image/png','image/webp','application/pdf'];
  if (allowed.indexOf(contentType) < 0) {
    return res.status(400).json({ error: 'Content type not allowed' });
  }

  // Generar la URL pre-firmada (AWS Signature V4)
  var now      = new Date();
  var dateStr  = now.toISOString().slice(0,10).replace(/-/g,'');          // 20260527
  var timeStr  = now.toISOString().replace(/[-:]/g,'').replace(/\..+/,'') + 'Z'; // 20260527T120000Z
  var region   = 'auto';
  var service  = 's3';
  var expires  = 300; // 5 minutos

  var objectKey  = filename;
  var credential = R2_ACCESS + '/' + dateStr + '/' + region + '/' + service + '/aws4_request';

  var queryParams = [
    'X-Amz-Algorithm=AWS4-HMAC-SHA256',
    'X-Amz-Credential=' + encodeURIComponent(credential),
    'X-Amz-Date=' + timeStr,
    'X-Amz-Expires=' + expires,
    'X-Amz-SignedHeaders=host'
  ].join('&');

  var canonicalRequest = [
    'PUT',
    '/' + objectKey,
    queryParams,
    'host:' + R2_HOST + '\n',
    'host',
    'UNSIGNED-PAYLOAD'
  ].join('\n');

  var stringToSign = [
    'AWS4-HMAC-SHA256',
    timeStr,
    dateStr + '/' + region + '/' + service + '/aws4_request',
    sha256Hex(canonicalRequest)
  ].join('\n');

  var signingKey = hmacSha256(
    hmacSha256(
      hmacSha256(
        hmacSha256('AWS4' + R2_SECRET, dateStr),
        region
      ),
      service
    ),
    'aws4_request'
  );

  var signature = hmacSha256(signingKey, stringToSign, 'hex');

  var uploadUrl = 'https://' + R2_HOST + '/' + objectKey +
    '?' + queryParams + '&X-Amz-Signature=' + signature;

  // URL pública para leer la foto después (requiere bucket público en Cloudflare)
  var publicUrl = 'https://pub-' + R2_ACCOUNT + '.r2.dev/' + objectKey;

  return res.status(200).json({
    uploadUrl: uploadUrl,
    publicUrl: publicUrl,
    expiresIn: expires
  });
};
