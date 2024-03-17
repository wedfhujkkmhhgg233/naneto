const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

function randomString(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function encodeSig(data) {
    const sortedData = Object.keys(data).sort().reduce((obj, key) => {
        obj[key] = data[key];
        return obj;
    }, {});
    const dataStr = Object.entries(sortedData).map(([key, value]) => `${key}=${value}`).join('');
    return crypto.createHash('md5').update(dataStr + '62f8ce9f74b12f84c123cc23437a4a32').digest('hex');
}

function convertCookie(session) {
    return session.map(item => `${item.name}=${item.value}`).join('; ');
}

async function convertToken(token) {
    try {
        const response = await axios.get(`https://api.facebook.com/method/auth.getSessionforApp?format=json&access_token=${token}&new_app_id=275254692598279`);
        return response.data.access_token;
    } catch (error) {
        throw new Error('Failed to convert token');
    }
}

function convert2FA(twofactorCode) {
    const code = parseInt(twofactorCode);
    return isNaN(code) ? null : code;
}

async function makeRequest(email, password, twofactorCode) {
    const deviceID = crypto.randomUUID();
    const adid = crypto.randomUUID();
    const randomStr = randomString(24);

    const form = {
        adid,
        email,
        password,
        format: 'json',
        device_id: deviceID,
        cpl: 'true',
        family_device_id: deviceID,
        locale: 'en_US',
        client_country_code: 'US',
        credentials_type: 'device_based_login_password',
        generate_session_cookies: '1',
        generate_analytics_claim: '1',
        generate_machine_id: '1',
        currently_logged_in_userid: '0',
        irisSeqID: 1,
        try_num: '1',
        enroll_misauth: 'false',
        meta_inf_fbmeta: 'NO_FILE',
        source: 'login',
        machine_id: randomStr,
        fb_api_req_friendly_name: 'authenticate',
        fb_api_caller_class: 'com.facebook.account.login.protocol.Fb4aAuthHandler',
        api_key: '882a8490361da98702bf97a021ddc14d',
        access_token: '350685531728%7C62f8ce9f74b12f84c123cc23437a4a32',
    };

    form.sig = encodeSig(form);

    const headers = {
        'content-type': 'application/x-www-form-urlencoded',
        'x-fb-friendly-name': form.fb_api_req_friendly_name,
        'x-fb-http-engine': 'Liger',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    };

    const url = 'https://b-graph.facebook.com/auth/login';

    try {
        const response = await axios.post(url, form, { headers });

        if (response.status === 200) {
            let data = response.data;
            if ('session_cookies' in data) {
                data.cookies = convertCookie(data.session_cookies);
            }
            if ('access_token' in data) {
                data.access_token = await convertToken(data.access_token);
            }
            return {
                status: true,
                message: 'Retrieve information successfully!',
                data,
            };
        } else if (response.status === 401) {
            return {
                status: false,
                message: response.data.error.message,
            };
        } else if ('twofactor' in response.data && response.data.twofactor === '0') {
            return {
                status: false,
                message: 'Please enter the 2-factor authentication code!',
            };
        } else {
            twofactorCode = convert2FA(twofactorCode);
            if (twofactorCode !== null) {
                form.twofactor_code = twofactorCode;
                form.encrypted_msisdn = '';
                form.userid = response.data.error.error_data.uid;
                form.machine_id = response.data.error.error_data.machine_id;
                form.first_factor = response.data.error.error_data.login_first_factor;
                form.credentials_type = 'two_factor';
                form.sig = encodeSig(form);

                const secondResponse = await axios.post(url, form, { headers });

                if (secondResponse.status === 200) {
                    let data = secondResponse.data;
                    if ('session_cookies' in data) {
                        data.cookies = convertCookie(data.session_cookies);
                    }
                    if ('access_token' in data) {
                        data.access_token = await convertToken(data.access_token);
                    }
                    return {
                        status: true,
                        message: 'Retrieve information successfully!',
                        data,
                    };
                } else {
                    return {
                        status: false,
                        message: secondResponse.data,
                    };
                }
            } else {
                return {
                    status: false,
                    message: 'Invalid 2-factor authentication code!',
                };
            }
        }
    } catch (error) {
        return {
            status: false,
            message: 'Please check your account and password again!',
        };
    }
}

app.post('/login', async (req, res) => {
    const { email, password, twofactorCode } = req.body;
    const result = await makeRequest(email, password, twofactorCode);
    res.json(result);
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
          
