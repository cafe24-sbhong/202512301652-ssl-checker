document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('checkForm');
    const urlInput = document.getElementById('urlInput');
    const checkBtn = document.getElementById('checkBtn');
    const btnText = checkBtn.querySelector('.btn-text');
    const btnLoading = checkBtn.querySelector('.btn-loading');
    const errorDiv = document.getElementById('error');
    const resultsDiv = document.getElementById('results');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) return;

        // UI: Loading state
        setLoading(true);
        hideError();
        resultsDiv.style.display = 'none';

        try {
            const response = await fetch('/api/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || data.error || 'Failed to check certificate');
            }

            displayResults(data);
        } catch (error) {
            showError(error.message);
        } finally {
            setLoading(false);
        }
    });

    function setLoading(loading) {
        checkBtn.disabled = loading;
        btnText.style.display = loading ? 'none' : 'inline';
        btnLoading.style.display = loading ? 'inline' : 'none';
    }

    function showError(message) {
        errorDiv.textContent = `⚠️ ${message}`;
        errorDiv.style.display = 'block';
    }

    function hideError() {
        errorDiv.style.display = 'none';
    }

    function displayResults(data) {
        // Grade
        const gradeCircle = document.getElementById('gradeCircle');
        const grade = document.getElementById('grade');
        grade.textContent = data.grade;
        gradeCircle.className = 'grade-circle grade-' + data.grade.toLowerCase().replace('+', '-plus');

        // Hostname
        document.getElementById('hostname').textContent = data.hostname;

        // Summary
        document.getElementById('passCount').textContent = `${data.summary.passed} 통과`;
        document.getElementById('warningCount').textContent = `${data.summary.warnings} 경고`;
        document.getElementById('failCount').textContent = `${data.summary.failed} 실패`;

        // Validations
        const validationsDiv = document.getElementById('validations');
        validationsDiv.innerHTML = data.validations.map(v => `
            <div class="validation-item ${v.status}">
                <span class="icon">${getStatusIcon(v.status)}</span>
                <span class="name">${v.name}</span>
                <span class="message">${v.message}</span>
            </div>
        `).join('');

        // Certificate Info
        const cert = data.certificate;
        document.getElementById('certInfo').innerHTML = `
            <div class="info-row">
                <span class="label">주체 (Subject)</span>
                <span class="value">${cert.subject}</span>
            </div>
            <div class="info-row">
                <span class="label">발급자 (Issuer)</span>
                <span class="value">${cert.issuer}</span>
            </div>
            <div class="info-row">
                <span class="label">유효 기간</span>
                <span class="value">${formatDate(cert.validFrom)} ~ ${formatDate(cert.validTo)}</span>
            </div>
            <div class="info-row">
                <span class="label">남은 일수</span>
                <span class="value ${getDaysClass(cert.daysRemaining)}">${cert.daysRemaining}일</span>
            </div>
            <div class="info-row">
                <span class="label">시리얼 번호</span>
                <span class="value">${cert.serialNumber}</span>
            </div>
            <div class="info-row">
                <span class="label">서명 알고리즘</span>
                <span class="value">${cert.signatureAlgorithm}</span>
            </div>
            <div class="info-row">
                <span class="label">키 크기</span>
                <span class="value">${cert.keySize} bits</span>
            </div>
            <div class="info-row">
                <span class="label">지문 (SHA-256)</span>
                <span class="value" style="font-size: 0.75rem;">${cert.fingerprint}</span>
            </div>
            ${cert.subjectAltNames ? `
            <div class="info-row">
                <span class="label">대체 이름 (SAN)</span>
                <span class="value">${formatSAN(cert.subjectAltNames)}</span>
            </div>
            ` : ''}
        `;

        // Connection Info
        document.getElementById('connInfo').innerHTML = `
            <div class="info-row">
                <span class="label">TLS 프로토콜</span>
                <span class="value ${getProtocolClass(data.connection.protocol)}">${data.connection.protocol}</span>
            </div>
            <div class="info-row">
                <span class="label">암호화 스위트</span>
                <span class="value">${data.connection.cipher}</span>
            </div>
            <div class="info-row">
                <span class="label">신뢰 상태</span>
                <span class="value ${data.connection.authorized ? 'good' : 'danger'}">
                    ${data.connection.authorized ? '✓ 신뢰됨' : '✗ 신뢰되지 않음'}
                </span>
            </div>
        `;

        // Certificate Chain
        const chainDiv = document.getElementById('chainInfo');
        chainDiv.innerHTML = data.chain.map((cert, index) => `
            <div class="chain-item">
                <div class="chain-label">${getChainLabel(index, data.chain.length, cert.isSelfSigned)}</div>
                <div class="chain-subject">${cert.subject}</div>
                <div class="chain-details">
                    <span>📅 ${formatDate(cert.validFrom)} ~ ${formatDate(cert.validTo)}</span>
                    <span>🔑 ${cert.bits || '?'} bits</span>
                    <span>✍️ ${cert.signatureAlgorithm}</span>
                </div>
            </div>
        `).join('');

        // Checked At
        document.getElementById('checkedAt').textContent = new Date(data.checkedAt).toLocaleString('ko-KR');

        resultsDiv.style.display = 'block';
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function getStatusIcon(status) {
        switch (status) {
            case 'pass': return '✅';
            case 'warning': return '⚠️';
            case 'fail': return '❌';
            default: return '❓';
        }
    }

    function formatDate(dateStr) {
        try {
            return new Date(dateStr).toLocaleDateString('ko-KR', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
        } catch {
            return dateStr;
        }
    }

    function formatSAN(san) {
        return san.split(', ').map(s => s.replace('DNS:', '')).join(', ');
    }

    function getDaysClass(days) {
        if (days <= 0) return 'danger';
        if (days <= 30) return 'warning';
        return 'good';
    }

    function getProtocolClass(protocol) {
        if (['TLSv1.3', 'TLSv1.2'].includes(protocol)) return 'good';
        if (['TLSv1.1', 'TLSv1'].includes(protocol)) return 'warning';
        return 'danger';
    }

    function getChainLabel(index, total, isSelfSigned) {
        if (index === 0) return '🔒 서버 인증서 (End-Entity)';
        if (index === total - 1) {
            return isSelfSigned ? '🏛️ 루트 인증서 (Root CA)' : '📜 중간 인증서 (Intermediate)';
        }
        return '📜 중간 인증서 (Intermediate)';
    }

    // Auto-focus input
    urlInput.focus();

    // Handle example domains
    const examples = ['google.com', 'github.com', 'cloudflare.com'];
    urlInput.placeholder = examples[Math.floor(Math.random() * examples.length)];
});
