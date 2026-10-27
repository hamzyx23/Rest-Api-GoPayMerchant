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
app.use('/gopay', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', index: false }));

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
  return { token: req.header('x-gopay-token') || req.query.token || null, apikey: null, entry: null, source: 'token' };
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
// This legacy GoBiz Web OTP flow is not the same as the documented GoBiz OAuth
// partner flow. Delivery method and SMS content belong to the upstream service.
const OTP_COOLDOWN_SECONDS = 60;
const OTP_WINDOW_SECONDS = 15 * 60;
const OTP_MAX_WINDOW = 5;
const otpLocalLimits = new Map();
const otpVerifyLocalLimits = new Map();
function otpHash(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function otpRetry(res, seconds, message = 'Tunggu sebelum meminta kode kembali') {
  const retry = Math.max(1, Math.ceil(Number(seconds) || OTP_COOLDOWN_SECONDS));
  res.set('Retry-After', String(retry));
  return res.status(429).json({ success:false, code:'OTP_COOLDOWN', error:message, retry_after_seconds:retry });
}
function sweepOtpLimits(now) {
  if (otpLocalLimits.size < 5000 && otpVerifyLocalLimits.size < 5000) return;
  for (const [key, item] of otpLocalLimits) if (item.windowEnd <= now) otpLocalLimits.delete(key);
  for (const [key, item] of otpVerifyLocalLimits) if (item.until <= now) otpVerifyLocalLimits.delete(key);
}
// Distributed atomic cooldown when Redis exists; local fallback only protects one Node process.
async function reserveOtp(phone) {
  const id = otpHash(phone), now = Date.now();
  sweepOtpLimits(now);
  if (redis) {
    const cooldownKey = `auth:otp:cooldown:${id}`;
    const countKey = `auth:otp:attempts:${id}`;
    const reserved = await redis.set(cooldownKey, '1', { nx:true, ex:OTP_COOLDOWN_SECONDS });
    if (reserved !== 'OK') {
      const left = Number(await redis.ttl(cooldownKey));
      return { allowed:false, retry: left > 0 ? left : OTP_COOLDOWN_SECONDS };
    }
    const count = Number(await redis.incr(countKey));
    if (count === 1) await redis.expire(countKey, OTP_WINDOW_SECONDS);
    if (count > OTP_MAX_WINDOW) {
      const left = Number(await redis.ttl(countKey));
      return { allowed:false, retry:left > 0 ? left : OTP_WINDOW_SECONDS };
    }
    return { allowed:true };
  }
  let entry = otpLocalLimits.get(id);
  if (!entry || entry.windowEnd <= now) entry = { windowEnd:now + OTP_WINDOW_SECONDS * 1000, nextAllowed:0, count:0 };
  if (entry.nextAllowed > now) return { allowed:false, retry:Math.ceil((entry.nextAllowed - now)/1000) };
  if (entry.count >= OTP_MAX_WINDOW) return { allowed:false, retry:Math.ceil((entry.windowEnd - now)/1000) };
  entry.count++;
  entry.nextAllowed = now + OTP_COOLDOWN_SECONDS * 1000;
  otpLocalLimits.set(id, entry);
  return { allowed:true };
}
function authFailure(error, action, started) {
  const elapsed = Date.now() - started;
  const status = Number(error?.response?.status || 0);
  const timeout = error?.code === 'ECONNABORTED' || error?.code === 'ETIMEDOUT';
  const code = timeout ? 'UPSTREAM_TIMEOUT' : status === 429 ? 'UPSTREAM_LIMIT' : status >= 500 ? 'UPSTREAM_UNAVAILABLE' : status === 400 || status === 401 || status === 403 ? 'UPSTREAM_REJECTED' : 'UPSTREAM_NETWORK_ERROR';
  console.warn(`[auth] ${action} result=${code} upstream_status=${status || '-'} elapsed_ms=${elapsed}`);
  const message = {
    UPSTREAM_TIMEOUT:'Layanan autentikasi belum merespons. Status pengiriman OTP tidak diketahui; jangan meminta berkali-kali.',
    UPSTREAM_LIMIT:'Layanan autentikasi sedang membatasi permintaan. Coba kembali sesuai jeda.',
    UPSTREAM_UNAVAILABLE:'Layanan autentikasi sedang tidak tersedia. Coba kembali nanti.',
    UPSTREAM_REJECTED:'Permintaan ditolak layanan autentikasi. Periksa nomor, kode, atau ketersediaan akses merchant.',
    UPSTREAM_NETWORK_ERROR:'Tidak dapat menghubungi layanan autentikasi. Periksa koneksi server.'
  }[code];
  return { status:timeout ? 504 : status === 429 ? 429 : status === 400 || status === 401 || status === 403 ? 400 : 502, code, message };
}
function getOtpPhone(raw) {
  if (typeof raw !== 'string' || !/^[+\d\s()-]{9,24}$/.test(raw)) return null;
  let phone = raw.replace(/\D/g, '');
  if (phone.startsWith('62')) phone = phone.slice(2);
  else if (phone.startsWith('0')) phone = phone.slice(1);
  return /^\d{9,13}$/.test(phone) ? phone : null;
}
app.get('/gopay/health', (req, res) => res.json({ success: true, version: '2.1.0', status: 'online' }));
app.all('/gopay/otp', async (req, res) => {
  if (!['GET','POST'].includes(req.method)) return res.sendStatus(405);
  if (req.method === 'GET') res.set('Deprecation', 'true'); // Legacy compatibility; use POST for new clients.
  const phone = getOtpPhone(req.method === 'POST' ? req.body?.phone : req.query?.phone);
  if (!phone) return res.status(400).json({ success:false, code:'INVALID_PHONE', error:'Nomor merchant tidak valid (9–13 digit setelah +62).' });
  let gate;
  try { gate = await reserveOtp(phone); }
  catch (_) { return res.status(503).json({ success:false, code:'OTP_LIMIT_UNAVAILABLE', error:'Sistem pembatasan OTP belum tersedia. Coba kembali nanti.' }); }
  if (!gate.allowed) return otpRetry(res, gate.retry);
  const started = Date.now();
  try {
    const data = await goMerchant.requestOtp(phone);
    // Never tell the client SMS/WhatsApp was delivered: this only confirms an upstream challenge.
    const otpToken = data?.data?.otp_token || data?.otp_token;
    if (typeof otpToken !== 'string' || !otpToken) {
      console.warn(`[auth] requestOtp result=CHALLENGE_MISSING elapsed_ms=${Date.now()-started}`);
      return res.status(502).json({ success:false, code:'CHALLENGE_MISSING', error:'Layanan autentikasi tidak memberikan token verifikasi; status pengiriman pesan tidak diketahui.', retry_after_seconds:OTP_COOLDOWN_SECONDS });
    }
    console.info(`[auth] requestOtp result=CHALLENGE_ACCEPTED elapsed_ms=${Date.now()-started}`);
    res.json({ success:true, data:{ otp_token:otpToken, message:'Permintaan kode diterima layanan autentikasi. Penerimaan pesan belum dapat dipastikan.', retry_after_seconds:OTP_COOLDOWN_SECONDS, delivery_method:'unknown' } });
  } catch (error) {
    const f = authFailure(error, 'requestOtp', started);
    if (f.status === 429) res.set('Retry-After', String(OTP_COOLDOWN_SECONDS));
    res.status(f.status).json({ success:false, code:f.code, error:f.message, retry_after_seconds:OTP_COOLDOWN_SECONDS });
  }
});
app.all('/gopay/token', async (req, res) => {
  if (!['GET','POST'].includes(req.method)) return res.sendStatus(405);
  if (req.method === 'GET') res.set('Deprecation', 'true'); // Older clients may still use GET; never use it for new credentials.
  const {otp, otp_token:otpToken} = (req.method === 'POST' ? req.body : req.query) || {};
  if (typeof otp !== 'string' || !/^\d{4,8}$/.test(otp) || typeof otpToken !== 'string' || otpToken.length < 5 || otpToken.length > 4096) {
    return res.status(400).json({ success:false, code:'INVALID_OTP', error:'Isi kode OTP 4–8 digit dan token challenge yang valid.' });
  }
  const key = otpHash(otpToken), now = Date.now();
  let entry = otpVerifyLocalLimits.get(key);
  if (!entry || entry.until <= now) entry = {count:0, until:now + 10 * 60 * 1000};
  if (entry.count >= 8) return otpRetry(res, Math.ceil((entry.until-now)/1000), 'Terlalu banyak percobaan verifikasi. Minta challenge baru nanti.');
  entry.count++;
  otpVerifyLocalLimits.set(key, entry);
  const started = Date.now();
  try {
    const data = await goMerchant.verifyOtp(otp, otpToken);
    console.info(`[auth] verifyOtp result=VERIFIED elapsed_ms=${Date.now()-started}`);
    otpVerifyLocalLimits.delete(key);
    res.json({ success:true, data });
  } catch (error) {
    const f = authFailure(error, 'verifyOtp', started);
    res.status(f.status).json({ success:false, code:f.code, error:f.message });
  }
});
// Never accept refresh tokens in a URL, where they can appear in access logs.
app.all('/gopay/refresh', async (req, res) => {
  if (!['GET','POST'].includes(req.method)) return res.sendStatus(405);
  if (req.method === 'GET') res.set('Deprecation', 'true'); // Retained solely for backwards compatibility.
  try {
    const refreshToken = req.method === 'POST' ? req.body?.refresh_token : req.query?.refresh_token;
    if (!refreshToken || typeof refreshToken !== 'string') return res.status(400).json({ success:false, error:'refresh_token wajib diisi' });
    const data = await goMerchant.refreshToken(refreshToken);
    res.json({ success:true, data });
  } catch (e) {
    res.status(401).json({ success:false, error:'Refresh sesi tidak berhasil' });
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
app.all('/gopay/qris/create', async (req, res) => {
  if (!['GET','POST'].includes(req.method)) return res.sendStatus(405);
  try {
    const { amount, static_qr } = req.method === 'POST' ? (req.body || {}) : req.query;
    if (!amount || !static_qr) {
      return res.status(400).json({ success: false, error: 'Parameter amount dan static_qr wajib diisi' });
    }
    const data = await goMerchant.createDynamicQRIS(amount, static_qr);
    const qrBuffer = Buffer.isBuffer(data.qr_buffer) ? data.qr_buffer : Buffer.from(data.qr_buffer.data);
    // POST is privacy-preserving (inline image). Legacy GET keeps its former
    // public-image-host behavior to avoid breaking existing external clients.
    let imageUrl = 'data:image/png;base64,' + qrBuffer.toString('base64');
    if (req.method === 'GET') {
      try { imageUrl = await toUrl(qrBuffer, 'pixhost.to'); }
      catch (_) { /* local data URL fallback */ }
    }
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

// Merchant ownership is verified server-side before any phone-keyed Redis operation.
function normalizePhone(value) {
  let p = String(value || '').replace(/\D/g, '');
  if (p.startsWith('62')) p = p.slice(2);
  if (p.startsWith('0')) p = p.slice(1);
  return p;
}
async function requireMerchantOwnership(req, res, next) {
  try {
    const meta = await getTokenMeta(req);
    if (!meta.token) return res.status(401).json({ success:false, error:'Login merchant diperlukan' });
    const userInfo = await goMerchant.getMe(meta.token);
    const user = userInfo?.user || {};
    const accountPhone = normalizePhone(user.phone || user.phone_number || user.mobile_number);
    const requestedPhone = normalizePhone(req.body?.phone || req.query.phone);
    if (!accountPhone || !requestedPhone || accountPhone !== requestedPhone) {
      return res.status(403).json({ success:false, error:'Nomor merchant tidak dapat diverifikasi dari akun GoPay' });
    }
    req.merchantAccessToken = meta.token;
    next();
  } catch (error) {
    res.status(401).json({ success:false, error:'Sesi merchant tidak dapat diverifikasi' });
  }
}

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

app.post('/gopay/qris/saved', requireMerchantOwnership, async (req, res) => {
  try {
    if (!storageConfigured(res)) return;
    const { phone, static_qr } = req.body || {};
    if (!phone || !static_qr) return res.status(400).json({ success: false, error: 'phone dan static_qr wajib' });
    await redis.set(`qris:${phone}`, static_qr);
    res.json({ success: true, storage: 'redis' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/gopay/qris/saved', requireMerchantOwnership, async (req, res) => {
  try {
    if (!storageConfigured(res)) return;
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ success: false, error: 'phone wajib' });
    const qr = await redis.get(`qris:${phone}`);
    res.json({ success: true, static_qr: qr || null, storage: 'redis' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.delete('/gopay/qris/saved', requireMerchantOwnership, async (req, res) => {
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

app.post('/gopay/apikey', requireMerchantOwnership, async (req, res) => {
  try {
    if (!storageConfigured(res)) return;
    const { phone, refresh_token, prefix = 'GoPay_' } = req.body || {};
    const access_token = req.merchantAccessToken;
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

app.get('/gopay/apikey', requireMerchantOwnership, async (req, res) => {
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

app.delete('/gopay/apikey', requireMerchantOwnership, async (req, res) => {
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