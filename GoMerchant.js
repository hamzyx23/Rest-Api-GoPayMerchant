const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');

class GoMerchant {
    constructor() {
        this.baseUrl = 'https://api.gobiz.co.id';
        this.clientId = 'go-biz-web-new';
        this.appId = 'go-biz-web-dashboard';
        this.uniqueId = uuidv4();
        // Bound network waits; this does not control how fast a carrier delivers an OTP.
        this.authTimeoutMs = Math.max(8000, Math.min(30000, Number(process.env.GOPAY_AUTH_TIMEOUT_MS) || 20000));
    }

    headers(token = null) {
        const h = {
            'Accept': 'application/json, text/plain, */*',
            'Authentication-Type': 'go-id',
            'X-PhoneMake': 'Android 10',
            'X-PhoneModel': 'K',
            'x-DeviceOS': 'Web',
            'X-Platform': 'Web',
            'X-User-Type': 'merchant',
            'x-appId': this.appId,
            'x-uniqueid': this.uniqueId,
            'X-AppVersion': 'platform-v3.101.0-8918927d',
            'Gojek-Country-Code': 'ID',
            'Gojek-Timezone': 'Asia/Jakarta',
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36'
        };
        if (token) h['Authorization'] = `Bearer ${token}`;
        return h;
    }

    convertCRC16(str) {
        let crc = 0xFFFF;
        const strlen = str.length;
        for (let c = 0; c < strlen; c++) {
            crc ^= str.charCodeAt(c) << 8;
            for (let i = 0; i < 8; i++) {
                if (crc & 0x8000) crc = (crc << 1) ^ 0x1021;
                else crc = crc << 1;
            }
        }
        let hex = crc & 0xFFFF;
        hex = ("000" + hex.toString(16).toUpperCase()).slice(-4);
        return hex;
    }

    // Parses EMV/QRIS top-level TLV and rejects truncated/duplicated fields.
    parseQRIS(raw) {
        if (typeof raw !== 'string' || raw.length < 28 || raw.length > 2048) {
            throw new Error('Payload QRIS statis tidak valid');
        }
        const tags = [];
        let position = 0;
        const seen = new Set();
        while (position < raw.length) {
            const tag = raw.slice(position, position + 2);
            const len = raw.slice(position + 2, position + 4);
            if (!/^\d{2}$/.test(tag) || !/^\d{2}$/.test(len)) throw new Error('Format TLV QRIS tidak valid');
            const count = Number(len);
            position += 4;
            if (position + count > raw.length) throw new Error('Payload QRIS terpotong');
            if (seen.has(tag)) throw new Error('Tag QRIS duplikat: ' + tag);
            seen.add(tag);
            tags.push({ tag, value: raw.slice(position, position + count) });
            position += count;
        }
        if (tags[0]?.tag !== '00' || tags[0]?.value !== '01') throw new Error('Header QRIS tidak sesuai');
        if (tags.at(-1)?.tag !== '63' || tags.at(-1)?.value?.length !== 4) throw new Error('CRC QRIS wajib di bagian akhir');
        if (!/^[0-9A-Fa-f]{4}$/.test(tags.at(-1).value) || this.convertCRC16(raw.slice(0, -4)) !== tags.at(-1).value.toUpperCase()) {
            throw new Error('Checksum CRC QRIS statis tidak cocok');
        }
        if (!tags.some(t => t.tag === '58' && t.value === 'ID')) throw new Error('Kode negara QRIS harus ID');
        if (!tags.some(t => t.tag === '53' && t.value === '360')) throw new Error('Mata uang QRIS harus IDR (360)');
        return tags;
    }

    async createDynamicQRIS(amount, staticQr) {
        const n = Number(amount);
        if (!Number.isSafeInteger(n) || n < 1 || n > 100000000) {
            throw new Error('Nominal QRIS harus bilangan bulat Rp1–Rp100.000.000');
        }
        const tags = this.parseQRIS(String(staticQr || '').trim()).filter(t => t.tag !== '63' && t.tag !== '54');
        const format = tags.find(t => t.tag === '01');
        if (format) format.value = '12';
        else tags.splice(1, 0, { tag:'01', value:'12' });
        const countryIndex = tags.findIndex(t => t.tag === '58');
        tags.splice(countryIndex, 0, { tag:'54', value:String(n) });
        const payload = tags.map(({tag,value}) => {
            const length = value.length;
            if (length > 99) throw new Error('Field QRIS terlalu panjang');
            return tag + String(length).padStart(2,'0') + value;
        }).join('') + '6304';
        const result = payload + this.convertCRC16(payload);
        const qrCodeBuffer = await QRCode.toBuffer(result, { type: 'png', errorCorrectionLevel: 'M', margin: 2 });
        return { qr_buffer:qrCodeBuffer, qr_string:result, amount:n, created_at:new Date().toISOString() };
    }

    async requestOtp(phoneNumber) {
        const payload = { client_id: this.clientId, phone_number: phoneNumber, country_code: '62' };
        const response = await axios.post(`${this.baseUrl}/goid/login/request`, payload, { headers: this.headers(), timeout: this.authTimeoutMs });
        return response.data;
    }

    async verifyOtp(otp, otpToken) {
        const payload = { client_id: this.clientId, data: { otp, otp_token: otpToken }, grant_type: 'otp' };
        const response = await axios.post(`${this.baseUrl}/goid/token`, payload, { headers: this.headers(), timeout: this.authTimeoutMs });
        return response.data;
    }

    async refreshToken(refreshToken) {
        const payload = { client_id: this.clientId, grant_type: 'refresh_token', data: { refresh_token: refreshToken } };
        const response = await axios.post(`${this.baseUrl}/goid/token`, payload, { headers: this.headers() });
        return response.data;
    }

    async getMe(accessToken) {
        const response = await axios.get(`${this.baseUrl}/v1/users/me`, { headers: this.headers(accessToken) });
        return response.data;
    }

    async getPayouts(accessToken) {
        const response = await axios.get(`${this.baseUrl}/v1/merchants/payouts?page=1&per=50`, { headers: this.headers(accessToken) });
        return response.data;
    }

    async getJournals(accessToken, merchantId, startTime = null) {
        const dateTo = new Date().toISOString();
        const dateFrom = startTime || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
        const payload = {
            from: 0, size: 50,
            sort: { time: { order: 'desc' } },
            included_categories: { incoming: ['transaction_share', 'action'] },
            query: [{
                clauses: [
                    { field: 'metadata.transaction.status', op: 'in', value: ['settlement', 'capture'] },
                    { field: 'metadata.transaction.transaction_time', op: 'gte', value: dateFrom },
                    { field: 'metadata.transaction.transaction_time', op: 'lte', value: dateTo },
                    { field: 'metadata.transaction.merchant_id', op: 'equal', value: merchantId }
                ],
                op: 'and'
            }]
        };
        const response = await axios.post(`${this.baseUrl}/journals/search`, payload, {
            headers: { ...this.headers(accessToken), 'accept': 'application/vnd.journal.v1+json' }
        });
        return response.data;
    }
}

module.exports = GoMerchant;