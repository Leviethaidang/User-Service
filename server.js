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

// Hàm xây dựng tên hiển thị cho phương thức thanh toán
function buildPaymentDisplayName(methodType, data) {
    if (methodType === "COD") {
        return "Thanh toán khi nhận hàng";
    }

    if (methodType === "MOMO") {
        return `MoMo - ${data.momoPhoneNumber}`;
    }

    if (methodType === "BANK") {
        return `${data.bankName} - ${data.bankAccountNumber}`;
    }

    return "Phương thức thanh toán";
}

// Middleware xác thực JWT Token từ header Authorization
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
            groups: payload["cognito:groups"] || [],
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
// Middleware kiểm tra quyền Admin
function adminMiddleware(req, res, next) {
    const groups = req.user.groups || [];

    if (!groups.includes("Admin")) {
        return res.status(403).json({
            error: "Bạn không có quyền Admin!"
        });
    }

    next();
}
function isValidGroup(groupName) {
    return ["Admin", "Customer"].includes(groupName);
}

async function addUserToGroup(username, groupName) {
    if (!groupName) return;

    await cognito.adminAddUserToGroup({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Username: username,
        GroupName: groupName
    }).promise();
}

async function removeUserFromGroup(username, groupName) {
    if (!groupName) return;

    await cognito.adminRemoveUserFromGroup({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Username: username,
        GroupName: groupName
    }).promise();
}

// ==========================================
// ROUTE 1: ĐĂNG KÝ (SIGN UP)
// ==========================================
app.post('/api/users/auth/register', async (req, res) => {
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
app.post('/api/users/auth/confirm-register', async (req, res) => {
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
app.post('/api/users/auth/login', async (req, res) => {
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
app.get('/api/users/me', authMiddleware, async (req, res) => {
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
app.put('/api/users/me', authMiddleware, async (req, res) => {
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
app.post('/api/users/me/verify-email', authMiddleware, async (req, res) => {
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
// ==========================================
// ROUTE 7: LẤY DANH SÁCH PHƯƠNG THỨC THANH TOÁN
// ==========================================
app.get('/api/user/payment-methods', authMiddleware, async (req, res) => {
    const userId = req.user.sub;

    try {
        const [userRows] = await dbPool.execute(
            `
            SELECT default_payment_method_id
            FROM users
            WHERE user_id = ?
            `,
            [userId]
        );

        if (userRows.length === 0) {
            return res.status(404).json({
                error: "Không tìm thấy user!"
            });
        }

        const [paymentRows] = await dbPool.execute(
            `
            SELECT
                payment_method_id,
                user_id,
                method_type,
                momo_phone_number,
                bank_name,
                bank_account_number,
                display_name,
                is_system_default,
                created_at,
                updated_at
            FROM user_payment_methods
            WHERE user_id = ?
            ORDER BY is_system_default DESC, created_at ASC
            `,
            [userId]
        );

        return res.json({
            message: "Lấy danh sách phương thức thanh toán thành công!",
            defaultPaymentMethodId: userRows[0].default_payment_method_id,
            paymentMethods: paymentRows
        });

    } catch (error) {
        console.error("Lỗi lấy payment methods:", error);
        return res.status(500).json({
            error: "Không thể lấy danh sách phương thức thanh toán!"
        });
    }
});

// ==========================================
// ROUTE 8: THÊM PHƯƠNG THỨC THANH TOÁN
// ==========================================
app.post('/api/user/payment-methods', authMiddleware, async (req, res) => {
    const userId = req.user.sub;

    const {
        methodType,
        momoPhoneNumber,
        bankName,
        bankAccountNumber
    } = req.body || {};

    if (!["MOMO", "BANK"].includes(methodType)) {
        return res.status(400).json({
            error: "methodType không hợp lệ. Chỉ chấp nhận MOMO hoặc BANK"
        });
    }

    if (methodType === "MOMO") {
        if (!momoPhoneNumber || !momoPhoneNumber.trim()) {
            return res.status(400).json({
                error: "Vui lòng nhập số điện thoại MoMo"
            });
        }
    }

    if (methodType === "BANK") {
        if (!bankName || !bankName.trim()) {
            return res.status(400).json({
                error: "Vui lòng chọn ngân hàng"
            });
        }

        if (!bankAccountNumber || !bankAccountNumber.trim()) {
            return res.status(400).json({
                error: "Vui lòng nhập số tài khoản ngân hàng"
            });
        }
    }

    const displayName = buildPaymentDisplayName(methodType, {
        momoPhoneNumber,
        bankName,
        bankAccountNumber
    });

    try {
        const [result] = await dbPool.execute(
            `
            INSERT INTO user_payment_methods (
                user_id,
                method_type,
                momo_phone_number,
                bank_name,
                bank_account_number,
                display_name,
                is_system_default
            )
            VALUES (?, ?, ?, ?, ?, ?, 0)
            `,
            [
                userId,
                methodType,
                methodType === "MOMO" ? momoPhoneNumber.trim() : null,
                methodType === "BANK" ? bankName.trim() : null,
                methodType === "BANK" ? bankAccountNumber.trim() : null,
                displayName
            ]
        );

        const [rows] = await dbPool.execute(
            `
            SELECT
                payment_method_id,
                user_id,
                method_type,
                momo_phone_number,
                bank_name,
                bank_account_number,
                display_name,
                is_system_default,
                created_at,
                updated_at
            FROM user_payment_methods
            WHERE payment_method_id = ?
              AND user_id = ?
            `,
            [result.insertId, userId]
        );

        return res.status(201).json({
            message: "Thêm phương thức thanh toán thành công!",
            paymentMethod: rows[0]
        });

    } catch (error) {
        console.error("Lỗi thêm payment method:", error);
        return res.status(500).json({
            error: "Không thể thêm phương thức thanh toán!"
        });
    }
});

// ==========================================
// ROUTE 9: XÓA PHƯƠNG THỨC THANH TOÁN
// ==========================================
app.delete('/api/user/payment-methods/:paymentMethodId', authMiddleware, async (req, res) => {
    const userId = req.user.sub;
    const { paymentMethodId } = req.params;

    let connection;

    try {
        connection = await dbPool.getConnection();

        await connection.beginTransaction();

        const [methodRows] = await connection.execute(
            `
            SELECT
                payment_method_id,
                method_type,
                is_system_default
            FROM user_payment_methods
            WHERE payment_method_id = ?
              AND user_id = ?
            `,
            [paymentMethodId, userId]
        );

        if (methodRows.length === 0) {
            await connection.rollback();
            return res.status(404).json({
                error: "Không tìm thấy phương thức thanh toán cần xóa!"
            });
        }

        const targetMethod = methodRows[0];

        if (targetMethod.method_type === "COD" || targetMethod.is_system_default === 1) {
            await connection.rollback();
            return res.status(400).json({
                error: "Không thể xóa phương thức COD mặc định của hệ thống!"
            });
        }

        const [userRows] = await connection.execute(
            `
            SELECT default_payment_method_id
            FROM users
            WHERE user_id = ?
            `,
            [userId]
        );

        const currentDefaultId = userRows[0].default_payment_method_id;

        if (Number(currentDefaultId) === Number(paymentMethodId)) {
            const [codRows] = await connection.execute(
                `
                SELECT payment_method_id
                FROM user_payment_methods
                WHERE user_id = ?
                  AND method_type = 'COD'
                  AND is_system_default = 1
                LIMIT 1
                `,
                [userId]
            );

            if (codRows.length === 0) {
                await connection.rollback();
                return res.status(500).json({
                    error: "Không tìm thấy COD mặc định để chuyển về!"
                });
            }

            await connection.execute(
                `
                UPDATE users
                SET default_payment_method_id = ?
                WHERE user_id = ?
                `,
                [codRows[0].payment_method_id, userId]
            );
        }

        await connection.execute(
            `
            DELETE FROM user_payment_methods
            WHERE payment_method_id = ?
              AND user_id = ?
            `,
            [paymentMethodId, userId]
        );

        await connection.commit();

        return res.json({
            message: "Xóa phương thức thanh toán thành công!"
        });

    } catch (error) {
        if (connection) await connection.rollback();

        console.error("Lỗi xóa payment method:", error);
        return res.status(500).json({
            error: "Không thể xóa phương thức thanh toán!"
        });

    } finally {
        if (connection) connection.release();
    }
});

// ==========================================
// ROUTE 10: CHỌN PHƯƠNG THỨC THANH TOÁN MẶC ĐỊNH
// ==========================================
app.put('/api/user/payment-methods/:paymentMethodId/default', authMiddleware, async (req, res) => {
    const userId = req.user.sub;
    const { paymentMethodId } = req.params;

    try {
        const [rows] = await dbPool.execute(
            `
            SELECT payment_method_id
            FROM user_payment_methods
            WHERE payment_method_id = ?
              AND user_id = ?
            `,
            [paymentMethodId, userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                error: "Không tìm thấy phương thức thanh toán của bạn!"
            });
        }

        await dbPool.execute(
            `
            UPDATE users
            SET default_payment_method_id = ?
            WHERE user_id = ?
            `,
            [paymentMethodId, userId]
        );

        return res.json({
            message: "Đã đặt phương thức thanh toán mặc định!"
        });

    } catch (error) {
        console.error("Lỗi set default payment method:", error);
        return res.status(500).json({
            error: "Không thể đặt phương thức thanh toán mặc định!"
        });
    }
});

// ==========================================
// ADMIN ROUTE 1: LẤY DANH SÁCH USERS
// ==========================================
app.get('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const [rows] = await dbPool.execute(
            `
            SELECT
                user_id,
                full_name,
                email,
                phone_number,
                default_shipping_address,
                status,
                created_at,
                updated_at
            FROM users
            ORDER BY created_at DESC
            `
        );

        return res.json({
            message: "Lấy danh sách users thành công!",
            users: rows
        });

    } catch (error) {
        console.error("Lỗi lấy danh sách users:", error);
        return res.status(500).json({
            error: "Không thể lấy danh sách users!"
        });
    }
});
// ==========================================
// ADMIN ROUTE 2: TẠO USER MỚI
// ==========================================
app.post('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
    const {
        fullName,
        email,
        phoneNumber,
        password,
        defaultShippingAddress,
        groupName = "Customer"
    } = req.body || {};

    if (!fullName || !email || !phoneNumber || !password) {
        return res.status(400).json({
            error: "Vui lòng nhập đầy đủ fullName, email, phoneNumber, password"
        });
    }

    if (!isValidEmail(email)) {
        return res.status(400).json({
            error: "Email không hợp lệ"
        });
    }

    if (!phoneNumber.startsWith("+")) {
        return res.status(400).json({
            error: "Số điện thoại cần dùng định dạng quốc tế, ví dụ +84901234567"
        });
    }

    if (!isValidGroup(groupName)) {
        return res.status(400).json({
            error: "Group không hợp lệ. Chỉ chấp nhận Admin hoặc Customer"
        });
    }

    let createdCognitoUser = false;

    try {
        const createResult = await cognito.adminCreateUser({
            UserPoolId: process.env.COGNITO_USER_POOL_ID,
            Username: email,
            MessageAction: "SUPPRESS",
            UserAttributes: [
                { Name: "email", Value: email },
                { Name: "email_verified", Value: "true" },
                { Name: "name", Value: fullName },
                { Name: "phone_number", Value: phoneNumber },
                { Name: "phone_number_verified", Value: "true" }
            ]
        }).promise();

        createdCognitoUser = true;

        await cognito.adminSetUserPassword({
            UserPoolId: process.env.COGNITO_USER_POOL_ID,
            Username: email,
            Password: password,
            Permanent: true
        }).promise();

        await addUserToGroup(email, groupName);

        const cognitoSubAttr = createResult.User.Attributes.find(attr => attr.Name === "sub");
        const userId = cognitoSubAttr.Value;

        await dbPool.execute(
            `
            INSERT INTO users (
                user_id,
                full_name,
                email,
                phone_number,
                default_shipping_address,
                status
            )
            VALUES (?, ?, ?, ?, ?, 'ACTIVE')
            `,
            [
                userId,
                fullName.trim(),
                email.trim(),
                phoneNumber.trim(),
                defaultShippingAddress ? defaultShippingAddress.trim() : null
            ]
        );

        return res.status(201).json({
            message: "Admin đã tạo user thành công!",
            user: {
                user_id: userId,
                full_name: fullName,
                email,
                phone_number: phoneNumber,
                default_shipping_address: defaultShippingAddress || null,
                groupName
            }
        });

    } catch (error) {
        console.error("Lỗi admin tạo user:", error);

        if (createdCognitoUser) {
            try {
                await cognito.adminDeleteUser({
                    UserPoolId: process.env.COGNITO_USER_POOL_ID,
                    Username: email
                }).promise();
            } catch (cleanupError) {
                console.error("Lỗi cleanup Cognito user:", cleanupError);
            }
        }

        if (error.code === "UsernameExistsException") {
            return res.status(400).json({
                error: "User này đã tồn tại trong Cognito!"
            });
        }

        if (error.code === "ER_DUP_ENTRY") {
            return res.status(400).json({
                error: "Email này đã tồn tại trong database!"
            });
        }

        return res.status(500).json({
            error: error.message || "Không thể tạo user!"
        });
    }
});
// ==========================================
// ADMIN ROUTE 3: SỬA USER
// ==========================================
app.put('/api/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    const { userId } = req.params;

    const {
        fullName,
        email,
        phoneNumber,
        defaultShippingAddress,
        status,
        groupName
    } = req.body || {};

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
                default_shipping_address,
                status
            FROM users
            WHERE user_id = ?
            `,
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                error: "Không tìm thấy user cần sửa!"
            });
        }

        const currentUser = rows[0];

        const nextFullName =
            fullName !== undefined ? fullName.trim() : currentUser.full_name;

        const nextEmail =
            email !== undefined ? email.trim() : currentUser.email;

        const nextPhoneNumber =
            phoneNumber !== undefined ? phoneNumber.trim() : currentUser.phone_number;

        const nextAddress =
            defaultShippingAddress !== undefined
                ? defaultShippingAddress.trim()
                : currentUser.default_shipping_address;

        const nextStatus =
            status !== undefined ? status.trim() : currentUser.status;

        if (!["ACTIVE", "DISABLED"].includes(nextStatus)) {
            return res.status(400).json({
                error: "Status không hợp lệ. Chỉ chấp nhận ACTIVE hoặc DISABLED"
            });
        }

        if (!nextFullName) {
            return res.status(400).json({
                error: "Họ và tên không được để trống"
            });
        }

        if (!nextEmail || !isValidEmail(nextEmail)) {
            return res.status(400).json({
                error: "Email không hợp lệ"
            });
        }

        if (!nextPhoneNumber || !nextPhoneNumber.startsWith("+")) {
            return res.status(400).json({
                error: "Số điện thoại cần dùng định dạng quốc tế, ví dụ +84901234567"
            });
        }

        if (groupName !== undefined && !isValidGroup(groupName)) {
            return res.status(400).json({
                error: "Group không hợp lệ. Chỉ chấp nhận Admin hoặc Customer"
            });
        }

        const cognitoUsername = currentUser.email;

        const cognitoAttributes = [
            { Name: "name", Value: nextFullName },
            { Name: "email", Value: nextEmail },
            { Name: "email_verified", Value: "true" },
            { Name: "phone_number", Value: nextPhoneNumber },
            { Name: "phone_number_verified", Value: "true" }
        ];

        await cognito.adminUpdateUserAttributes({
            UserPoolId: process.env.COGNITO_USER_POOL_ID,
            Username: cognitoUsername,
            UserAttributes: cognitoAttributes
        }).promise();
        
        if (nextStatus === "DISABLED") {
            await cognito.adminDisableUser({
                UserPoolId: process.env.COGNITO_USER_POOL_ID,
                Username: cognitoUsername
            }).promise();

            await cognito.adminUserGlobalSignOut({
                UserPoolId: process.env.COGNITO_USER_POOL_ID,
                Username: cognitoUsername
            }).promise();
        }

        if (nextStatus === "ACTIVE") {
            await cognito.adminEnableUser({
                UserPoolId: process.env.COGNITO_USER_POOL_ID,
                Username: cognitoUsername
            }).promise();
        }

        if (groupName !== undefined) {
            await removeUserFromGroup(cognitoUsername, "Admin");
            await removeUserFromGroup(cognitoUsername, "Customer");
            await addUserToGroup(cognitoUsername, groupName);
        }

        await connection.execute(
            `
            UPDATE users
            SET
                full_name = ?,
                email = ?,
                phone_number = ?,
                default_shipping_address = ?,
                status = ?
            WHERE user_id = ?
            `,
            [
                nextFullName,
                nextEmail,
                nextPhoneNumber,
                nextAddress || null,
                nextStatus || "ACTIVE",
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
                status,
                created_at,
                updated_at
            FROM users
            WHERE user_id = ?
            `,
            [userId]
        );

        return res.json({
            message: "Admin đã cập nhật user thành công!",
            user: updatedRows[0]
        });

    } catch (error) {
        console.error("Lỗi admin sửa user:", error);

        if (error.code === "ER_DUP_ENTRY") {
            return res.status(400).json({
                error: "Email này đã tồn tại trong database!"
            });
        }

        if (error.code === "AliasExistsException") {
            return res.status(400).json({
                error: "Email hoặc số điện thoại đã được dùng bởi tài khoản Cognito khác!"
            });
        }

        return res.status(500).json({
            error: error.message || "Không thể sửa user!"
        });

    } finally {
        if (connection) connection.release();
    }
});
// ==========================================
// ADMIN ROUTE 4: XÓA USER
// ==========================================
app.delete('/api/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    const { userId } = req.params;

    if (userId === req.user.sub) {
        return res.status(400).json({
            error: "Admin không thể tự xóa chính mình!"
        });
    }

    let connection;

    try {
        connection = await dbPool.getConnection();

        const [rows] = await connection.execute(
            `
            SELECT user_id, email
            FROM users
            WHERE user_id = ?
            `,
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                error: "Không tìm thấy user cần xóa!"
            });
        }

        const targetUser = rows[0];

        await cognito.adminDeleteUser({
            UserPoolId: process.env.COGNITO_USER_POOL_ID,
            Username: targetUser.email
        }).promise();

        await connection.execute(
            `
            DELETE FROM users
            WHERE user_id = ?
            `,
            [userId]
        );

        return res.json({
            message: "Admin đã xóa user thành công!"
        });

    } catch (error) {
        console.error("Lỗi admin xóa user:", error);
        return res.status(500).json({
            error: error.message || "Không thể xóa user!"
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