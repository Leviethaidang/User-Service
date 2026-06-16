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

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: "Không tìm thấy Token. Vui lòng đăng nhập!"
        });
    }

    const token = authHeader.split(' ')[1];

    try {
        const payload = await verifier.verify(token);

        req.user = {
            sub: payload.sub,
            username: payload.username || payload["cognito:username"] || payload.sub,
            accessToken: token,
            payload
        };

        next();
    } catch (error) {
        console.error("Lỗi verify token:", error);
        return res.status(401).json({
            error: "Token không hợp lệ hoặc đã hết hạn!"
        });
    }
}

function getAttributeValue(attributes, name) {
    const found = attributes.find(attr => attr.Name === name);
    return found ? found.Value : null;
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
app.get('/api/user/profile', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.sub;

        const [rows] = await dbPool.execute(
            `
            SELECT 
                user_id,
                full_name,
                email,
                phone_number,
                default_shipping_address,
                created_at,
                updated_at
            FROM users
            WHERE user_id = ?
            `,
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                error: "Không tìm thấy profile của người dùng trong DB!"
            });
        }

        return res.json({
            message: "Lấy thông tin thành công!",
            profile: rows[0]
        });

    } catch (error) {
        console.error("Lỗi lấy profile:", error);
        return res.status(500).json({
            error: "Lỗi hệ thống!"
        });
    }
});
// ==========================================
// ROUTE 5: CẬP NHẬT PROFILE (CẦN ĐĂNG NHẬP)
// ==========================================
app.put('/api/user/profile', authMiddleware, async (req, res) => {
    const {
        fullName,
        email,
        phoneNumber,
        defaultShippingAddress
    } = req.body || {};

    const userId = req.user.sub;
    const cognitoUsername = req.user.username;

    let connection;

    try {
        connection = await dbPool.getConnection();

        const [rows] = await connection.execute(
            `
            SELECT 
                user_id,
                full_name,
                email,
                phone_number,
                default_shipping_address
            FROM users
            WHERE user_id = ?
            `,
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                error: "Không tìm thấy profile để cập nhật!"
            });
        }

        const currentProfile = rows[0];

        const nextFullName =
            fullName !== undefined ? fullName.trim() : currentProfile.full_name;

        const requestedEmail =
            email !== undefined ? email.trim() : currentProfile.email;

        const nextPhoneNumber =
            phoneNumber !== undefined ? phoneNumber.trim() : currentProfile.phone_number;

        const nextAddress =
            defaultShippingAddress !== undefined
                ? defaultShippingAddress.trim()
                : currentProfile.default_shipping_address;

        if (!nextFullName) {
            return res.status(400).json({
                error: "Họ và tên không được để trống"
            });
        }
        if (!nextPhoneNumber) {
            return res.status(400).json({
                error: "Số điện thoại không được để trống"
            });
        }
        if (!requestedEmail || !isValidEmail(requestedEmail)) {
            return res.status(400).json({
                error: "Email không hợp lệ"
            });
        }

        if (nextPhoneNumber && !nextPhoneNumber.startsWith('+')) {
            return res.status(400).json({
                error: "Số điện thoại cần dùng định dạng quốc tế, ví dụ +84901234567"
            });
        }

        const emailChanged = requestedEmail !== currentProfile.email;
        const phoneChanged = nextPhoneNumber !== currentProfile.phone_number;
        const nameChanged = nextFullName !== currentProfile.full_name;

        const cognitoAttributes = [];

        if (nameChanged) {
            cognitoAttributes.push({
                Name: 'name',
                Value: nextFullName
            });
        }

        if (emailChanged) {
            cognitoAttributes.push({
                Name: 'email',
                Value: requestedEmail
            });

            // Không set email_verified = true
            // Để Cognito gửi mã xác minh email mới.
        }

        if (phoneChanged) {
            cognitoAttributes.push(
                {
                    Name: 'phone_number',
                    Value: nextPhoneNumber
                },
                {
                    Name: 'phone_number_verified',
                    Value: 'true'
                }
            );
        }

        if (cognitoAttributes.length > 0) {
            await cognito.adminUpdateUserAttributes({
                UserPoolId: process.env.COGNITO_USER_POOL_ID,
                Username: cognitoUsername,
                UserAttributes: cognitoAttributes
            }).promise();
        }

        // Không update email trong DB nếu emailChanged.
        // Email chỉ update vào DB sau khi user xác minh mã email.
        await connection.execute(
            `
            UPDATE users
            SET
                full_name = ?,
                phone_number = ?,
                default_shipping_address = ?
            WHERE user_id = ?
            `,
            [
                nextFullName,
                nextPhoneNumber || null,
                nextAddress || null,
                userId
            ]
        );

        const [updatedRows] = await connection.execute(
            `
            SELECT 
                user_id,
                full_name,
                email,
                phone_number,
                default_shipping_address,
                created_at,
                updated_at
            FROM users
            WHERE user_id = ?
            `,
            [userId]
        );

        return res.json({
            message: emailChanged
                ? "Profile đã cập nhật. Vui lòng kiểm tra email mới để lấy mã xác minh."
                : "Cập nhật profile thành công!",
            emailVerificationRequired: emailChanged,
            pendingEmail: emailChanged ? requestedEmail : null,
            profile: updatedRows[0]
        });

    } catch (error) {
        console.error("Lỗi cập nhật profile:", error);

        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({
                error: "Email này đã tồn tại trong database!"
            });
        }

        if (error.code === 'AliasExistsException') {
            return res.status(400).json({
                error: "Email hoặc số điện thoại này đã được dùng bởi tài khoản Cognito khác!"
            });
        }

        return res.status(500).json({
            error: error.message || "Không thể cập nhật profile!"
        });

    } finally {
        if (connection) connection.release();
    }
});
// ==========================================
// ROUTE 6: XÁC MINH EMAIL MỚI (CẦN ĐĂNG NHẬP)
// ==========================================
app.post('/api/user/profile/verify-email', authMiddleware, async (req, res) => {
    const { code } = req.body || {};
    const userId = req.user.sub;
    const accessToken = req.user.accessToken;

    if (!code) {
        return res.status(400).json({
            error: "Vui lòng nhập mã xác minh email"
        });
    }

    let connection;

    try {
        // Xác minh email mới trong Cognito bằng AccessToken của user hiện tại.
        await cognito.verifyUserAttribute({
            AccessToken: accessToken,
            AttributeName: 'email',
            Code: code
        }).promise();

        // Sau khi verify xong, lấy lại email mới từ Cognito.
        const cognitoUser = await cognito.getUser({
            AccessToken: accessToken
        }).promise();

        const verifiedEmail = getAttributeValue(cognitoUser.UserAttributes, 'email');

        if (!verifiedEmail) {
            return res.status(400).json({
                error: "Không lấy được email đã xác minh từ Cognito!"
            });
        }

        connection = await dbPool.getConnection();

        await connection.execute(
            `
            UPDATE users
            SET email = ?
            WHERE user_id = ?
            `,
            [verifiedEmail, userId]
        );

        const [updatedRows] = await connection.execute(
            `
            SELECT 
                user_id,
                full_name,
                email,
                phone_number,
                default_shipping_address,
                created_at,
                updated_at
            FROM users
            WHERE user_id = ?
            `,
            [userId]
        );

        return res.json({
            message: "Xác minh email mới thành công!",
            profile: updatedRows[0]
        });

    } catch (error) {
        console.error("Lỗi xác minh email mới:", error);

        if (error.code === 'CodeMismatchException') {
            return res.status(400).json({
                error: "Mã xác minh không đúng!"
            });
        }

        if (error.code === 'ExpiredCodeException') {
            return res.status(400).json({
                error: "Mã xác minh đã hết hạn!"
            });
        }

        if (error.code === 'AliasExistsException') {
            return res.status(400).json({
                error: "Email này đã được dùng bởi tài khoản khác!"
            });
        }

        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({
                error: "Email này đã tồn tại trong database!"
            });
        }

        return res.status(500).json({
            error: error.message || "Không thể xác minh email mới!"
        });

    } finally {
        if (connection) connection.release();
    }
});

// Khởi chạy server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`User Service running on port ${PORT}`);
});