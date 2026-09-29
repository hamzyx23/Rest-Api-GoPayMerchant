const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');

class GoMerchant {
    constructor() {
        this.baseUrl = 'https://api.gobiz.co.id';
        this.clientId = 'go-biz-web-new';
        this.appId = 'go-biz-web-dashboard';
        this.uniqueId = uuidv4();
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

    async createDynamicQRIS(amount, staticQr) {
        let qrisData = staticQr.slice(0, -4);
        const step1 = qrisData.replace("010211", "010212");
        const step2 = step1.split("5802ID");
        const amountStr = amount.toString();
        let uang = "54" + ("0" + amountStr.length).slice(-2) + amountStr;
        uang += "5802ID";
        const result = step2[0] + uang + step2[1] + this.convertCRC16(step2[0] + uang + step2[1]);
        const qrCodeBuffer = await QRCode.toBuffer(result);
        return {
            qr_buffer: qrCodeBuffer,
            qr_string: result,
            amount: amount,
            created_at: new Date().toISOString()
        };
    }

    async requestOtp(phoneNumber) {
        const payload = { client_id: this.clientId, phone_number: phoneNumber, country_code: '62' };
        const response = await axios.post(`${this.baseUrl}/goid/login/request`, payload, { headers: this.headers() });
        return response.data;
    }

    async verifyOtp(otp, otpToken) {
        const payload = { client_id: this.clientId, data: { otp, otp_token: otpToken }, grant_type: 'otp' };
        const response = await axios.post(`${this.baseUrl}/goid/token`, payload, { headers: this.headers() });
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