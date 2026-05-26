// Expone la VAPID public key al cliente
module.exports = function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.status(200).json({ key: process.env.VAPID_PUBLIC_KEY || '' });
};
