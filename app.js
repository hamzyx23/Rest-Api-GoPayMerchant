const express = require('express');
const path = require('path');
const crypto = require('crypto');
const GoMerchant = require('./GoMerchant');

const { ImageUploadService } = require('node-upload-images');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const FormData = require('form-data');
const { Redis } = require('@upstash/redis');

const app = express();
const goMerchant = new GoMerchant();
const PORT = process.env.PORT || 3000;

app.set('json spaces', 2);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ============ REDIS (auto-detect env Vercel) ============
// Vercel Upstash integration bisa inject dengan beberapa skema nama:
// - KV_REST_API_URL / KV_REST_API_TOKEN  (paling umum di Vercel)
// - UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN  (dari Upstash langsung)
// - REDIS_REST_API_URL / REDIS_REST_API_TOKEN  (varian lain)
let redis = null;
(function initRedis() {
  const url =
    process.env.KV_REST_API_URL ||
    process.env.UPSTASH_REDIS_REST_URL ||
    process.env.REDIS_REST_API_URL;

  const token =
    process.env.KV_REST_API_TOKEN ||
    process.env.UPSTASH_REDIS_REST_TOKEN ||
    process.env.REDIS_REST_API_TOKEN;

  // Log semua kandidat — biar gampang debug kalau masih gagal
  console.log('[storage] env check:', {
    KV_REST_API_URL: !!process.env.KV_REST_API_URL,
    KV_REST_API_TOKEN: !!process.env.KV_REST_API_TOKEN,
    UPSTASH_REDIS_REST_URL: !!process.env.UPSTASH_REDIS_REST_URL,
    UPSTASH_REDIS_REST_TOKEN: !!process.env.UPSTASH_REDIS_REST_TOKEN,
    REDIS_REST_API_URL: !!process.env.REDIS_REST_API_URL,
    REDIS_REST_API_TOKEN: !!process.env.REDIS_REST_API_TOKEN,
  });

  if (!url || !token) {
    console.warn('[storage] ⚠️ Redis tidak terdeteksi — fallback localStorage (client)');
    return;
  }

  try {
    redis = new Redis({ url, token });
    console.log('[storage] ✅ Redis terhubung');
  } catch (e) {
    console.warn('[storage] ❌ Redis init error:', e.message);
  }
})();

// ============ TOKEN RESOLVER + AUTO-REFRESH ============
async function getTokenMeta(req) {
  const apikey =
    req.query.apikey ||
    req.header('x-api-key') ||
    (req.header('authorization') || '').replace(/^Bearer\s+/i, '');

  if (apikey && redis) {
    try {
      const raw = await redis.get(`apikey:${apikey}`);
      if (raw) {
        const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
        return { token: data.access_token, apikey, entry: data, source: 'apikey' };
      }
    } catch (_) {}
  }
  return { token: req.query.token || null, apikey: null, entry: null, source: 'token' };
}

async function tryRefresh(req, meta, fn) {
  if (!meta.apikey || !meta.entry?.refresh_token || !redis) throw new Error('no refresh');
  const r = await goMerchant.refreshToken(meta.entry.refresh_token);
  const d = r.data || r;
  const newAccess = d.access_token || d.data?.access_token;
  const newRefresh = d.refresh_token || d.data?.refresh_token || meta.entry.refresh_token;
  if (!newAccess) throw new Error('refresh failed');
  meta.entry.access_token = newAccess;
  meta.entry.refresh_token = newRefresh;
  await redis.set(`apikey:${meta.apikey}`, JSON.stringify(meta.entry));
  return await fn(newAccess);
}

async function withToken(req, fn) {
  const meta = await getTokenMeta(req);
  if (!meta.token) {
    const err = new Error('token/apikey wajib diisi');
    err.statusCode = 400;
    throw err;
  }
  try {
    return await fn(meta.token);
  } catch (e) {
    if (e?.response?.status === 401 && meta.source === 'apikey') {
      try { return await tryRefresh(req, meta, fn); }
      catch (_) { throw e; }
    }
    throw e;
  }
}

// ============ UPLOAD ============
async function toUrl(buffer, provider = 'pixhost.to') {
  if (!Buffer.isBuffer(buffer)) throw new Error('Input harus buffer');
  if (provider === 'catbox') {
    const form = new FormData();
    form.append('fileToUpload', buffer, 'file.png');
    form.append('reqtype', 'fileupload');
    const res = await fetch('https://catbox.moe/user/api.php', {
      method: 'POST', body: form, headers: form.getHeaders()
    });
    const text = await res.text();
    if (!text.startsWith('http')) throw new Error('Catbox upload gagal');
    return text;
  }
  const service = new ImageUploadService(provider);
  const { directLink } = await service.uploadFromBinary(buffer, 'qris.png');
  return directLink;
}

// ============ ROUTE ============
app.get('/', (req, res) => res.render('index'));

// ============ AUTH ============
app.get('/gopay/otp', async (req, res) => {
  try {
    let phone = req.query.phone;
    if (!phone) return res.status(400).json({ success: false, error: 'phone wajib diisi' });
    if (phone.startsWith('62')) phone = phone.slice(2);
    if (phone.startsWith('0')) phone = phone.slice(1);
    phone = phone.replace(/\D/g, '');
    if (phone.length < 9 || phone.length > 13) {
      return res.status(400).json({ success: false, error: 'Nomor telepon tidak valid' });
    }
    const data = await goMerchant.requestOtp(phone);
    res.json({
      success: true,
      data: {
        otp_token: data.data?.otp_token || data.otp_token,
        message: 'Kode OTP 4 digit telah dikirim via SMS'
      }
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.response?.data || e.message });
  }
});

app.get('/gopay/token', async (req, res) => {
  try {
    const { otp, otp_token } = req.query;
    if (!otp || !otp_token) return res.status(400).json({ success: false, error: 'otp dan otp_token wajib diisi' });
    if (!/^\d{4}$/.test(otp)) return res.status(400).json({ success: false, error: 'OTP harus 4 digit' });
    const data = await goMerchant.verifyOtp(otp, otp_token);
    res.json({ success: true, data });
  } catch (e) {
    res.status(400).json({ success: false, error: e.response?.data || e.message });
  }
});

app.get('/gopay/refresh', async (req, res) => {
  try {
    const refreshToken = req.query.refresh_token;
    if (!refreshToken) return res.status(400).json({ success: false, error: 'refresh_token wajib diisi' });
    const data = await goMerchant.refreshToken(refreshToken);
    res.json({ success: true, data });
  } catch (e) {
    res.status(401).json({ success: false, error: e.response?.data || e.message });
  }
});

// ============ MERCHANT ============
app.get('/gopay/validate', async (req, res) => {
  try {
    const payload = await withToken(req, async (token) => {
      const data = await goMerchant.getMe(token);
      return { user: data.user, access_token: token };
    });
    res.json({ success: true, ...payload });
  } catch (e) {
    res.status(e.statusCode || 401).json({ success: false, error: e.response?.data || e.message });
  }
});

app.get('/gopay/me', async (req, res) => {
  try {
    const data = await withToken(req, (token) => goMerchant.getMe(token));
    res.json({ success: true, data });
  } catch (e) {
    res.status(e.statusCode || 400).json({ success: false, error: e.response?.data || e.message });
  }
});

app.get('/gopay/profile', async (req, res) => {
  try {
    const profile = await withToken(req, async (token) => {
      const me = await goMerchant.getMe(token);
      const u = me.user || {};
      const emailPrefix = (u.email || '').split('@')[0];
      const prettify = (s) => s
        ? s.replace(/[._\-+]+/g, ' ').trim().split(' ').filter(Boolean)
            .map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
        : null;
      const fullName =
        u.name || u.full_name || u.username || u.display_name || u.ktp_name ||
        prettify(emailPrefix) ||
        (u.phone ? 'Merchant ' + String(u.phone).slice(-4) : null) ||
        'Merchant';
      return {
        name: fullName,
        email: u.email || null,
        phone: u.phone || u.phone_number || null,
        merchant_id: u.merchant_id || null
      };
    });
    res.json({ success: true, profile });
  } catch (e) {
    res.status(e.statusCode || 400).json({ success: false, error: e.response?.data || e.message });
  }
});

app.get('/gopay/mutasi', async (req, res) => {
  try {
    const payload = await withToken(req, async (token) => {
      const user = await goMerchant.getMe(token);
      const startTime = req.query.start_time || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      const result = await goMerchant.getJournals(token, user.user.merchant_id, startTime);
      const data = (result.hits || [])
        .filter(item => item?.metadata?.transaction?.payment_type === 'qris')
        .map(item => {
          const aspi = item.metadata?.provider_metadata?.aspi;
          let amountRupiah;
          const a = aspi?.data?.amount, j = item.amount;
          if (a != null && !isNaN(Number(a))) amountRupiah = Number(a);
          else if (j != null && !isNaN(Number(j))) amountRupiah = Number(j) / 100;
          else amountRupiah = 0;
          return {
            id: item.id,
            reference_id: item.reference_id,
            status: item.status,
            time: item.time,
            amount: amountRupiah,
            issuer: aspi?.issuer || null,
            acquirer: aspi?.acquirer || null,
            merchant_name: aspi?.data?.merchant_name || null
          };
        });
      return { total: data.length, data };
    });
    res.json({ success: true, ...payload });
  } catch (e) {
    res.status(e.statusCode || 400).json({ success: false, error: e.response?.data || e.message });
  }
});

app.get('/gopay/payouts', async (req, res) => {
  try {
    const data = await withToken(req, (token) => goMerchant.getPayouts(token));
    res.json({ success: true, data });
  } catch (e) {
    res.status(e.statusCode || 400).json({ success: false, error: e.response?.data || e.message });
  }
});

// ============ QRIS ============
app.get('/gopay/qris/create', async (req, res) => {
  try {
    const { amount, static_qr } = req.query;
    if (!amount || !static_qr) {
      return res.status(400).json({ success: false, error: 'Parameter amount dan static_qr wajib diisi' });
    }
    const data = await goMerchant.createDynamicQRIS(amount, static_qr);
    const qrBuffer = Buffer.isBuffer(data.qr_buffer) ? data.qr_buffer : Buffer.from(data.qr_buffer.data);
    let imageUrl = null;
    try { imageUrl = await toUrl(qrBuffer, 'pixhost.to'); }
    catch (_) { imageUrl = 'data:image/png;base64,' + qrBuffer.toString('base64'); }
    res.json({
      success: true,
      image_url: imageUrl,
      amount: data.amount,
      qr_string: data.qr_string,
      created_at: data.created_at
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.response?.data || e.message });
  }
});

app.get('/gopay/qris/status', async (req, res) => {
  try {
    const { amount, created_at } = req.query;
    if (!amount || !created_at) {
      return res.status(400).json({ success: false, error: 'amount dan created_at wajib diisi' });
    }
    const payload = await withToken(req, async (token) => {
      const user = await goMerchant.getMe(token);
      const logs = await goMerchant.getJournals(token, user.user.merchant_id, created_at);
      const amountSearch = parseInt(amount, 10) * 100;
      const found = (logs.hits || []).find(h => {
        const txTime = new Date(h.time).getTime();
        const qrisTime = new Date(created_at).getTime();
        return h.amount === amountSearch && txTime >= qrisTime;
      });
      return { status: found ? 'PAID' : 'PENDING', data: found || null };
    });
    res.json({ success: true, ...payload });
  } catch (e) {
    res.status(e.statusCode || 400).json({ success: false, error: e.response?.data || e.message });
  }
});

// ============ QRIS SAVED STORAGE ============
function storageConfigured(res) {
  if (!redis) {
    res.status(503).json({
      success: false,
      error: 'Storage tidak tersedia (Redis off)',
      fallback: 'localStorage'
    });
    return false;
  }
  return true;
}

app.post('/gopay/qris/saved', async (req, res) => {
  try {
    if (!storageConfigured(res)) return;
    const { phone, static_qr } = req.body || {};
    if (!phone || !static_qr) return res.status(400).json({ success: false, error: 'phone dan static_qr wajib' });
    await redis.set(`qris:${phone}`, static_qr);
    res.json({ success: true, storage: 'redis' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/gopay/qris/saved', async (req, res) => {
  try {
    if (!storageConfigured(res)) return;
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ success: false, error: 'phone wajib' });
    const qr = await redis.get(`qris:${phone}`);
    res.json({ success: true, static_qr: qr || null, storage: 'redis' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.delete('/gopay/qris/saved', async (req, res) => {
  try {
    if (!storageConfigured(res)) return;
    const phone = req.body?.phone || req.query.phone;
    if (!phone) return res.status(400).json({ success: false, error: 'phone wajib' });
    await redis.del(`qris:${phone}`);
    res.json({ success: true, storage: 'redis' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============ API KEY STORAGE ============
function genApiKey(prefix) {
  const rand = crypto.randomBytes(24).toString('hex');
  return `${prefix}${rand}`;
}

function validatePrefix(prefix) {
  if (!prefix || prefix.length < 2 || prefix.length > 20) return false;
  return /^[A-Za-z0-9_.-]+$/.test(prefix);
}

app.post('/gopay/apikey', async (req, res) => {
  try {
    if (!storageConfigured(res)) return;
    const { phone, access_token, refresh_token, prefix = 'GoPay_' } = req.body || {};
    if (!phone || !access_token) return res.status(400).json({ success: false, error: 'phone dan access_token wajib' });
    if (!validatePrefix(prefix)) return res.status(400).json({ success: false, error: 'Prefix tidak valid (2-20 char alfanumerik + _ . -)' });

    const oldKey = await redis.get(`apikey_phone:${phone}`);
    if (oldKey) await redis.del(`apikey:${oldKey}`);

    const key = genApiKey(prefix);
    const data = {
      phone,
      access_token,
      refresh_token: refresh_token || null,
      prefix,
      created_at: new Date().toISOString()
    };
    await redis.set(`apikey:${key}`, JSON.stringify(data));
    await redis.set(`apikey_phone:${phone}`, key);

    res.json({ success: true, apikey: key, prefix, created_at: data.created_at, storage: 'redis' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/gopay/apikey', async (req, res) => {
  try {
    if (!storageConfigured(res)) return;
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ success: false, error: 'phone wajib' });
    const key = await redis.get(`apikey_phone:${phone}`);
    if (!key) return res.json({ success: true, apikey: null, storage: 'redis' });
    const raw = await redis.get(`apikey:${key}`);
    const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
    res.json({
      success: true,
      apikey: key,
      prefix: data?.prefix || 'GoPay_',
      created_at: data?.created_at || null,
      storage: 'redis'
    });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.delete('/gopay/apikey', async (req, res) => {
  try {
    if (!storageConfigured(res)) return;
    const phone = req.body?.phone || req.query.phone;
    if (!phone) return res.status(400).json({ success: false, error: 'phone wajib' });
    const key = await redis.get(`apikey_phone:${phone}`);
    if (key) await redis.del(`apikey:${key}`);
    await redis.del(`apikey_phone:${phone}`);
    res.json({ success: true, storage: 'redis' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`GoPay Merchant API running on http://localhost:${PORT}`));
}

module.exports = app;