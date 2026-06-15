require('dotenv').config();
const express = require('express');
const AWS = require('aws-sdk');
const mysql = require('mysql2/promise');
const { CognitoJwtVerifier } = require('aws-jwt-verify');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// 1. Cấu hình kết nối AWS Cognito
const cognito = new AWS.CognitoIdentityServiceProvider({
    region: process.env.AWS_REGION
});

// 2. Cấu hình kết nối MySQL Pool
const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10
});
// 3. Cấu hình Cognito JWT Verifier để xác thực Token
const verifier = CognitoJwtVerifier.create({
    userPoolId: process.env.COGNITO_USER_POOL_ID,
    tokenUse: "access",
    clientId: process.env.COGNITO_APP_CLIENT_ID
});

function generateSecretHash(username) {
    return crypto
        .createHmac('sha256', process.env.COGNITO_CLIENT_SECRET)
        .update(username + process.env.COGNITO_APP_CLIENT_ID)
        .digest('base64');
}

// ==========================================
// ROUTE 1: ĐĂNG KÝ (SIGN UP)
// ==========================================
app.post('/api/auth/register', async (req, res) => {
    const { fullName, email, phoneNumber, password } = req.body;

    if (!fullName || !email || !phoneNumber || !password) {
        return res.status(400).json({
            error: "Vui lòng nhập đầy đủ fullName, email, phoneNumber, password"
        });
    }

    const params = {
        ClientId: process.env.COGNITO_APP_CLIENT_ID,
        SecretHash: generateSecretHash(email),
        Username: email,
        Password: password,
        UserAttributes: [
            {
                Name: 'email',
                Value: email
            },
            {
                Name: 'name',
                Value: fullName
            },
            {
                Name: 'phone_number',
                Value: phoneNumber
            }
        ]
    };

    try {
        const result = await cognito.signUp(params).promise();

        return res.status(201).json({
            message: "Đăng ký thành công! Vui lòng kiểm tra mã xác nhận.",
            userSub: result.UserSub,
            userConfirmed: result.UserConfirmed
        });

    } catch (error) {
        console.error("Lỗi đăng ký Cognito:", error);

        return res.status(400).json({
            error: error.message
        });
    }
});
// ==========================================
// ROUTE 2: XÁC NHẬN ĐĂNG KÝ (CONFIRM SIGN UP)
// ==========================================
app.post('/api/auth/confirm-register', async (req, res) => {
    const { email, code } = req.body;

    if (!email || !code) {
        return res.status(400).json({
            error: "Vui lòng nhập email và mã xác nhận"
        });
    }

    const params = {
        ClientId: process.env.COGNITO_APP_CLIENT_ID,
        SecretHash: generateSecretHash(email),
        Username: email,
        ConfirmationCode: code
    };

    try {
        await cognito.confirmSignUp(params).promise();

        return res.json({
            message: "Xác nhận tài khoản thành công! Bạn có thể đăng nhập."
        });

    } catch (error) {
        console.error("Lỗi xác nhận đăng ký Cognito:", error);

        return res.status(400).json({
            error: error.message
        });
    }
});
// ==========================================
// ROUTE 3: ĐĂNG NHẬP (SIGN IN)
// ==========================================
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            error: "Vui lòng nhập email và password"
        });
    }
    
    const params = {
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: process.env.COGNITO_APP_CLIENT_ID,
        AuthParameters: {
            USERNAME: email,
            PASSWORD: password,
            SECRET_HASH: generateSecretHash(email)
        }
    };

    try {
        // Gửi thông tin lên Cognito để check tài khoản mật khẩu
        const authResult = await cognito.initiateAuth(params).promise();
        
        // Trả về bộ Token (IdToken, AccessToken, RefreshToken) cho Client
        return res.json({
            message: "Đăng nhập thành công!",
            tokens: authResult.AuthenticationResult
        });
    } catch (error) {
        console.error("Lỗi đăng nhập Cognito:", error);
        return res.status(400).json({ error: error.message });
    }
});

// ==========================================
// ROUTE 4: LẤY PROFILE (CẦN ĐĂNG NHẬP)
// ==========================================
app.get('/api/user/profile', async (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Không tìm thấy Token. Vui lòng đăng nhập!" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const payload = await verifier.verify(token);

        const userId = payload.sub;

        const [rows] = await dbPool.execute(
            'SELECT user_id, full_name, email, phone_number, default_shipping_address FROM users WHERE user_id = ?',
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: "Không tìm thấy profile của người dùng trong DB!" });
        }

        return res.json({
            message: "Lấy thông tin thành công!",
            profile: rows[0]
        });

    } catch (error) {
        console.error("Lỗi verify token hoặc lấy profile:", error);
        return res.status(401).json({ error: "Token không hợp lệ hoặc đã hết hạn!" });
    }
});

// Khởi chạy server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`User Service running on port ${PORT}`);
});