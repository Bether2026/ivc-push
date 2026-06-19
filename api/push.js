// IVC Seguridad — Vercel Function para Web Push
const webpush = require('web-push');

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'ivc2024secure';

// Puestos de gestión — los únicos que deben recibir push automáticos de
// novedades/incidencias con relevancia Alta o Urgente, y comunicaciones
// internas dirigidas a "gestión". NO son los agentes de puesto en general.
const PUESTOS_GESTION = ['Gerencia', 'Administración', 'Administrador', 'Responsable de turno'];

webpush.setVapidDetails(
  'mailto:seguridad@ivc.gob.ar',
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY
);

async function getSubscriptions() {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?select=*`, {
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`
    }
  });
  return res.ok ? await res.json() : [];
}

async function removeSubscription(id) {
  await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?id=eq.${id}`, {
    method: 'DELETE',
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`
    }
  });
}

async function enviarYResponder(subscriptions, title, message, urgent, res) {
  if (!subscriptions.length) return res.status(200).json({ sent: 0 });

  const payload = JSON.stringify({ title, body: message, urgent, tag: 'ivc-' + Date.now(), icon: '/favicon.ico' });

  let sent = 0;
  await Promise.all(subscriptions.map(async (sub) => {
    try {
      await webpush.sendNotification({ endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } }, payload);
      sent++;
    } catch (err) {
      if (err.statusCode === 410 || err.statusCode === 404) await removeSubscription(sub.id);
    }
  }));

  return res.status(200).json({ sent, total: subscriptions.length });
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const secret = req.headers['x-webhook-secret'] || req.query.secret;
  if (secret !== WEBHOOK_SECRET) return res.status(401).json({ error: 'Unauthorized' });

  const body = req.body;
  const record = body.record || body.new || body;

  let title = 'IVC Seguridad';
  let message = 'Nueva actualización';
  let urgent = false;
  let filtrarSoloGestion = false;

  if (record.relevancia === 'Urgente' || record.relevancia === 'Alta') {
    // Novedades con relevancia alta/urgente (incidencias, alertas operativas):
    // SOLO a puestos de gestión, nunca a todos los agentes de puesto.
    urgent = record.relevancia === 'Urgente';
    title = (urgent ? '🚨 URGENTE' : '⚠️ IMPORTANTE') + ' — ' + (record.puesto || 'Novedad');
    message = record.asunto || 'Nueva novedad';
    if (record.cargado_por) message += ' · ' + record.cargado_por;
    filtrarSoloGestion = true;
  } else if (record.importancia === 'Urgente' || record.importancia === 'Importante') {
    // Comunicaciones del módulo "Comunicaciones": respetan los destinatarios
    // que el usuario eligió al crearla. Si no especificó destinatarios
    // (campo vacío/null), es una comunicación general → va a todos.
    urgent = record.importancia === 'Urgente';
    title = (urgent ? '📢 URGENTE' : '📣 IMPORTANTE') + ' — Comunicación';
    message = record.titulo || record.mensaje || 'Nueva comunicación';
    const tieneDestinatarios = record.destinatarios && Array.isArray(record.destinatarios) && record.destinatarios.length > 0;
    if (tieneDestinatarios) {
      const subsAll = await getSubscriptions();
      const subsFiltradas = subsAll.filter((s) => record.destinatarios.indexOf(s.puesto) !== -1);
      return await enviarYResponder(subsFiltradas, title, message, urgent, res);
    }
    // Sin destinatarios específicos = comunicación general = va a todos (sin filtrar)
  } else {
    return res.status(200).json({ sent: 0, reason: 'not urgent' });
  }

  let subscriptions = await getSubscriptions();
  if (filtrarSoloGestion) {
    subscriptions = subscriptions.filter((s) => PUESTOS_GESTION.indexOf(s.puesto) !== -1);
  }

  return await enviarYResponder(subscriptions, title, message, urgent, res);
};
