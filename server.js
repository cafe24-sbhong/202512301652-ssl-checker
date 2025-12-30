const express = require('express');
const tls = require('tls');
const https = require('https');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// SSL Certificate Check Endpoint
app.post('/api/check', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        let hostname;
        try {
            const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
            hostname = parsed.hostname;
        } catch {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        const result = await checkSSLCertificate(hostname);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            error: 'Failed to check certificate',
            message: error.message
        });
    }
});

async function checkSSLCertificate(hostname) {
    return new Promise((resolve, reject) => {
        const options = {
            host: hostname,
            port: 443,
            servername: hostname,
            rejectUnauthorized: false,
            requestCert: true
        };

        const socket = tls.connect(options, () => {
            try {
                const cert = socket.getPeerCertificate(true);
                const authorized = socket.authorized;
                const authorizationError = socket.authorizationError;
                const protocol = socket.getProtocol();
                const cipher = socket.getCipher();

                if (!cert || Object.keys(cert).length === 0) {
                    socket.end();
                    return reject(new Error('No certificate found'));
                }

                const now = new Date();
                const validFrom = new Date(cert.valid_from);
                const validTo = new Date(cert.valid_to);
                const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

                // Build certificate chain
                const chain = [];
                let currentCert = cert;
                const visited = new Set();

                while (currentCert) {
                    const fingerprint = currentCert.fingerprint256 || currentCert.fingerprint;
                    if (visited.has(fingerprint)) break;
                    visited.add(fingerprint);

                    chain.push({
                        subject: formatDN(currentCert.subject),
                        issuer: formatDN(currentCert.issuer),
                        validFrom: currentCert.valid_from,
                        validTo: currentCert.valid_to,
                        serialNumber: currentCert.serialNumber,
                        fingerprint: currentCert.fingerprint256 || currentCert.fingerprint,
                        signatureAlgorithm: currentCert.sigalg || 'Unknown',
                        bits: currentCert.bits || 'Unknown',
                        isSelfSigned: isSelfSigned(currentCert)
                    });

                    currentCert = currentCert.issuerCertificate;
                    if (currentCert === cert) break; // Circular reference
                }

                // Validation checks
                const validations = [];

                // 1. Certificate validity period
                validations.push({
                    name: 'Certificate Validity',
                    status: now >= validFrom && now <= validTo ? 'pass' : 'fail',
                    message: now < validFrom
                        ? 'Certificate not yet valid'
                        : now > validTo
                            ? 'Certificate has expired'
                            : `Valid (${daysRemaining} days remaining)`
                });

                // 2. Expiration warning
                if (daysRemaining <= 30 && daysRemaining > 0) {
                    validations.push({
                        name: 'Expiration Warning',
                        status: 'warning',
                        message: `Certificate expires in ${daysRemaining} days`
                    });
                } else if (daysRemaining <= 0) {
                    validations.push({
                        name: 'Expiration Warning',
                        status: 'fail',
                        message: 'Certificate has expired'
                    });
                } else {
                    validations.push({
                        name: 'Expiration Warning',
                        status: 'pass',
                        message: `${daysRemaining} days until expiration`
                    });
                }

                // 3. Chain validation
                validations.push({
                    name: 'Certificate Chain',
                    status: chain.length > 1 ? 'pass' : 'warning',
                    message: chain.length > 1
                        ? `Chain complete (${chain.length} certificates)`
                        : 'Single certificate (no chain)'
                });

                // 4. Trust validation
                validations.push({
                    name: 'Trust Status',
                    status: authorized ? 'pass' : 'fail',
                    message: authorized
                        ? 'Certificate is trusted'
                        : `Not trusted: ${authorizationError || 'Unknown error'}`
                });

                // 5. Hostname match
                const hostnameMatch = checkHostnameMatch(cert, hostname);
                validations.push({
                    name: 'Hostname Match',
                    status: hostnameMatch ? 'pass' : 'fail',
                    message: hostnameMatch
                        ? 'Hostname matches certificate'
                        : 'Hostname does not match certificate'
                });

                // 6. Protocol check
                validations.push({
                    name: 'TLS Protocol',
                    status: isSecureProtocol(protocol) ? 'pass' : 'warning',
                    message: `Using ${protocol}`
                });

                // 7. Key strength
                const keyStrength = cert.bits || 0;
                validations.push({
                    name: 'Key Strength',
                    status: keyStrength >= 2048 ? 'pass' : keyStrength >= 1024 ? 'warning' : 'fail',
                    message: keyStrength ? `${keyStrength} bits` : 'Unknown'
                });

                // 8. Signature algorithm
                const sigAlg = cert.sigalg || '';
                const isWeakSig = sigAlg.toLowerCase().includes('sha1') || sigAlg.toLowerCase().includes('md5');
                validations.push({
                    name: 'Signature Algorithm',
                    status: isWeakSig ? 'warning' : 'pass',
                    message: sigAlg || 'Unknown'
                });

                // Calculate overall score
                const passCount = validations.filter(v => v.status === 'pass').length;
                const failCount = validations.filter(v => v.status === 'fail').length;
                const warningCount = validations.filter(v => v.status === 'warning').length;

                let grade = 'A+';
                if (failCount > 0) grade = 'F';
                else if (warningCount >= 3) grade = 'C';
                else if (warningCount >= 2) grade = 'B';
                else if (warningCount >= 1) grade = 'A';

                socket.end();

                resolve({
                    hostname,
                    grade,
                    summary: {
                        passed: passCount,
                        warnings: warningCount,
                        failed: failCount
                    },
                    certificate: {
                        subject: formatDN(cert.subject),
                        issuer: formatDN(cert.issuer),
                        validFrom: cert.valid_from,
                        validTo: cert.valid_to,
                        daysRemaining,
                        serialNumber: cert.serialNumber,
                        fingerprint: cert.fingerprint256 || cert.fingerprint,
                        subjectAltNames: cert.subjectaltname || '',
                        signatureAlgorithm: cert.sigalg || 'Unknown',
                        keySize: cert.bits || 'Unknown'
                    },
                    connection: {
                        protocol,
                        cipher: cipher ? cipher.name : 'Unknown',
                        authorized
                    },
                    chain,
                    validations,
                    checkedAt: new Date().toISOString()
                });

            } catch (error) {
                socket.end();
                reject(error);
            }
        });

        socket.on('error', (error) => {
            reject(new Error(`Connection failed: ${error.message}`));
        });

        socket.setTimeout(10000, () => {
            socket.destroy();
            reject(new Error('Connection timeout'));
        });
    });
}

function formatDN(dn) {
    if (!dn) return 'Unknown';
    if (typeof dn === 'string') return dn;

    const parts = [];
    if (dn.CN) parts.push(`CN=${dn.CN}`);
    if (dn.O) parts.push(`O=${dn.O}`);
    if (dn.OU) parts.push(`OU=${dn.OU}`);
    if (dn.L) parts.push(`L=${dn.L}`);
    if (dn.ST) parts.push(`ST=${dn.ST}`);
    if (dn.C) parts.push(`C=${dn.C}`);

    return parts.length > 0 ? parts.join(', ') : JSON.stringify(dn);
}

function isSelfSigned(cert) {
    if (!cert.subject || !cert.issuer) return false;
    return JSON.stringify(cert.subject) === JSON.stringify(cert.issuer);
}

function checkHostnameMatch(cert, hostname) {
    // Check CN
    if (cert.subject && cert.subject.CN) {
        if (matchHostname(cert.subject.CN, hostname)) return true;
    }

    // Check SAN
    if (cert.subjectaltname) {
        const sans = cert.subjectaltname.split(', ');
        for (const san of sans) {
            const match = san.match(/^DNS:(.+)$/i);
            if (match && matchHostname(match[1], hostname)) {
                return true;
            }
        }
    }

    return false;
}

function matchHostname(pattern, hostname) {
    if (pattern === hostname) return true;

    // Wildcard matching
    if (pattern.startsWith('*.')) {
        const suffix = pattern.slice(2);
        const hostParts = hostname.split('.');
        if (hostParts.length >= 2) {
            const hostSuffix = hostParts.slice(1).join('.');
            return hostSuffix === suffix;
        }
    }

    return false;
}

function isSecureProtocol(protocol) {
    const secure = ['TLSv1.2', 'TLSv1.3'];
    return secure.includes(protocol);
}

app.listen(PORT, () => {
    console.log(`SSL Checker running on port ${PORT}`);
});
