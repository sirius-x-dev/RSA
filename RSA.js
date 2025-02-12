const crypto = require('crypto');

// 1. 生成RSA密钥对
function generateKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
}

// 2. 计算POW（工作量证明）
function mineBlock(nickname) {
    let nonce = 0;
    while (true) {
        const data = nickname + nonce;
        const hash = crypto.createHash('sha256').update(data).digest('hex');
        if (hash.startsWith('0000')) {
            return { hash, nonce, data };
        }
        nonce++;
    }
}

// 3. 使用私钥签名
function sign(data, privateKey) {
    const signer = crypto.createSign('SHA256');
    signer.update(data);
    return signer.sign(privateKey, 'base64');
}

// 4. 使用公钥验证签名
function verify(data, signature, publicKey) {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(data);
    return verifier.verify(publicKey, signature, 'base64');
}

// 主函数
function main() {
    // 生成密钥对
    console.log('正在生成RSA密钥对...');
    const { publicKey, privateKey } = generateKeyPair();
    console.log('密钥对生成完成！\n');

    // 设置昵称并进行POW挖矿
    const nickname = 'sirius';
    console.log(`开始进行POW挖矿（寻找以0000开头的哈希值）...`);
    const { hash, nonce, data } = mineBlock(nickname);
    console.log(`挖矿成功！\n昵称: ${nickname}\nnonce: ${nonce}\n哈希值: ${hash}\n`);

    // 对数据进行签名
    console.log('使用私钥进行签名...');
    const signature = sign(data, privateKey);
    console.log(`签名完成！\n签名: ${signature}\n`);

    // 验证签名
    console.log('使用公钥验证签名...');
    const isValid = verify(data, signature, publicKey);
    console.log(`签名验证${isValid ? '成功' : '失败'}！`);
}

// 运行主函数
main();
