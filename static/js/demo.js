// Demo Page Specific JavaScript
// Extends main.js with demo functionality

// API Functions for Demo Page

// Text Encryption
async function encryptText() {
    const text = document.getElementById('text-input').value;
    const password = document.getElementById('text-password').value;
    
    // Check if algorithm requires password
    const algorithm = algorithms[currentDataType]?.find(alg => alg.name === selectedAlgorithm);
    const requiresPassword = !algorithm || algorithm.requiresPassword !== false;
    
    if (!text) {
        showError('text-result', 'Please enter text to encrypt');
        return;
    }
    
    if (requiresPassword && !password) {
        showError('text-result', 'Please enter a password');
        return;
    }
    showLoading('text-loading', true);
    hideElement('text-result');
    try {
        const response = await fetch('/api/encrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                data: text, data_type: 'text', algorithm: selectedAlgorithm, password: password
            })
        });
        const result = await response.json();
        showLoading('text-loading', false);
        if (result.success) {
            lastEncryptionResult = result;
            showResult('text-result', result);
            populateDecryptForm(result);
        } else {
            showError('text-result', result.error || 'Encryption failed');
        }
    } catch (error) {
        showLoading('text-loading', false);
        showError('text-result', 'Network error: ' + error.message);
    }
}

// Data Decryption
async function decryptData() {
    const encData = document.getElementById('decrypt-data-input').value;
    const password = document.getElementById('decrypt-password').value;
    const algorithm = document.getElementById('decrypt-algorithm').value;
    const metadataStr = document.getElementById('decrypt-metadata').value;
    
    // Check if algorithm requires password (check all data types for the algorithm)
    let requiresPassword = true;
    for (const dataType in algorithms) {
        const alg = algorithms[dataType].find(a => a.name === algorithm);
        if (alg && alg.requiresPassword === false) {
            requiresPassword = false;
            break;
        }
    }
    
    if (!encData) {
        showError('decrypt-result', 'Please enter encrypted data');
        return;
    }
    
    if (requiresPassword && !password) {
        showError('decrypt-result', 'Please enter decryption password');
        return;
    }
    let metadata = {};
    try {
        metadata = metadataStr ? JSON.parse(metadataStr) : {};
    } catch (e) {
        showError('decrypt-result', 'Invalid metadata JSON format.');
        return;
    }
    showLoading('decrypt-loading', true);
    hideElement('decrypt-result');
    try {
        const response = await fetch('/api/decrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ encrypted_data: encData, algorithm, password, metadata })
        });
        const result = await response.json();
        showLoading('decrypt-loading', false);
        if (result.success) {
            showResult('decrypt-result', `Decrypted Text: ${result.decrypted_data}`);
        } else {
            showError('decrypt-result', result.error || 'Decryption Failed');
        }
    } catch (error) {
        showLoading('decrypt-loading', false);
        showError('decrypt-result', 'Network error: ' + error.message);
    }
}

// File Encryption
async function encryptFile() {
    const fileInput = document.getElementById('file-input');
    const password = document.getElementById('file-password').value;
    
    // Check if algorithm requires password
    const algorithm = algorithms[currentDataType]?.find(alg => alg.name === selectedAlgorithm);
    const requiresPassword = !algorithm || algorithm.requiresPassword !== false;
    
    if (!fileInput.files[0]) {
        showError('file-result', 'Please select a file');
        return;
    }
    
    if (requiresPassword && !password) {
        showError('file-result', 'Please enter a password');
        return;
    }
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('algorithm', selectedAlgorithm);
    formData.append('password', password);
    showLoading('file-loading', true);
    hideElement('file-result');
    try {
        const response = await fetch('/api/encrypt/file', { method: 'POST', body: formData });
        const result = await response.json();
        showLoading('file-loading', false);
        if (result.success) {
            showResult('file-result', result);
        } else {
            showError('file-result', result.error || 'File encryption failed');
        }
    } catch (error) {
        showLoading('file-loading', false);
        showError('file-result', 'Network error: ' + error.message);
    }
}

// System Status
async function checkSystemStatus() {
    showLoading('status-loading', true);
    hideElement('status-result');
    try {
        const response = await fetch('/api/system/status');
        const result = await response.json();
        showLoading('status-loading', false);
        showResult('status-result', result, false);
    } catch (error) {
        showLoading('status-loading', false);
        showError('status-result', 'Failed to get system status: ' + error.message);
    }
}

// Test Encryption
async function testEncryption() {
    const algorithm = document.getElementById('test-algorithm').value;
    showLoading('test-loading', true);
    hideElement('test-result');
    try {
        const response = await fetch('/api/test/encryption', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ algorithm: algorithm })
        });
        const result = await response.json();
        showLoading('test-loading', false);
        if (result.success) {
            let testResult = `🧪 Encryption Test Results\n\n`;
            testResult += `Algorithm: ${result.algorithm}\n`;
            testResult += `Test Message: "${result.test_message}"\n\n`;
            testResult += `✅ Encryption: ${result.encryption_successful ? 'PASSED' : 'FAILED'}\n`;
            testResult += `✅ Decryption: ${result.decryption_successful ? 'PASSED' : 'FAILED'}\n`;
            testResult += `✅ Round Trip: ${result.round_trip_successful ? 'PASSED' : 'FAILED'}\n\n`;
            testResult += result.round_trip_successful ? `🎉 All tests passed!` : `❌ Test failed!`;
            showResult('test-result', testResult);
        } else {
            showError('test-result', result.error || 'Test failed');
        }
    } catch (error) {
        showLoading('test-loading', false);
        showError('test-result', 'Test failed: ' + error.message);
    }
}

// File Management
async function downloadFile() {
    const fileId = document.getElementById('download-file-id').value;
    const password = document.getElementById('download-password').value;
    if (!fileId || !password) {
        showError('download-result', 'Please enter file ID and password');
        return;
    }
    const url = `/api/download/${fileId}?password=${encodeURIComponent(password)}`;
    window.open(url, '_blank');
    showResult('download-result', 'Download initiated. Check browser for prompts. If the file does not download, the file ID or password may be incorrect.', false);
}

async function listFiles() {
    showLoading('files-loading', true);
    hideElement('files-result');
    try {
        const response = await fetch('/api/files');
        const result = await response.json();
        showLoading('files-loading', false);
        showResult('files-result', result, false);
    } catch (error) {
        showLoading('files-loading', false);
        showError('files-result', 'Failed to list files: ' + error.message);
    }
}

async function deleteFile() {
    const fileId = document.getElementById('delete-file-id').value;
    if (!fileId) {
        showError('delete-result', 'Please enter a file ID');
        return;
    }
    hideElement('delete-result');
    try {
        const response = await fetch(`/api/files/${fileId}`, { method: 'DELETE' });
        const result = await response.json();
        if (response.ok && result.success) {
            showResult('delete-result', result, false);
        } else {
            showError('delete-result', result.error || 'Deletion failed');
        }
    } catch (error) {
        showError('delete-result', 'Delete failed: ' + error.message);
    }
}

// Algorithm Comparison
async function compareAlgorithms() {
    const checkboxes = document.querySelectorAll('#compare-algorithm-list input[type="checkbox"]:checked');
    const selectedAlgos = Array.from(checkboxes).map(cb => cb.value);
    if (selectedAlgos.length < 2) {
        showError('compare-result', 'Please select at least 2 algorithms to compare');
        return;
    }
    showLoading('compare-loading', true);
    hideElement('compare-result');
    try {
        const response = await fetch('/api/algorithms/compare', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ algorithms: selectedAlgos, data_type: 'text' })
        });
        const result = await response.json();
        showLoading('compare-loading', false);
        if (result.success) {
            let formattedResult = `🆚 Algorithm Comparison\n\n`;
            formattedResult += `Data Type: ${result.data_type}\n`;
            formattedResult += `Algorithms: ${result.algorithms.join(', ')}\n\n`;
            if (result.comparison) {
                formattedResult += `📊 Security Scores:\n`;
                for (const [algo, score] of Object.entries(result.comparison.security || {})) formattedResult += `  • ${algo}: ${score}/100\n`;
                formattedResult += `\n⚡ Performance Scores:\n`;
                for (const [algo, score] of Object.entries(result.comparison.performance || {})) formattedResult += `  • ${algo}: ${score}/100\n`;
                formattedResult += `\n🎯 Use Cases:\n`;
                for (const [algo, cases] of Object.entries(result.comparison.use_cases || {})) formattedResult += `  • ${algo}: ${cases.join(', ')}\n`;
            }
            showResult('compare-result', formattedResult, false);
        } else {
            showError('compare-result', result.error || 'Comparison failed');
        }
    } catch (error) {
        showLoading('compare-loading', false);
        showError('compare-result', 'Comparison failed: ' + error.message);
    }
}

// Algorithm Recommendations
async function getRecommendations() {
    const dataType = document.getElementById('rec-data-type').value;
    const securityLevel = document.getElementById('rec-security-level').value;
    const performance = document.getElementById('rec-performance').value;
    showLoading('rec-loading', true);
    hideElement('rec-result');
    try {
        const response = await fetch('/api/algorithms/recommend', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                data_type: dataType,
                security_level: securityLevel,
                performance_priority: performance,
                use_case: 'general'
            })
        });
        const result = await response.json();
        showLoading('rec-loading', false);
        if (result.success) {
            let formattedResult = `💡 Algorithm Recommendations\n\n`;
            formattedResult += `For: ${result.data_type} encryption\n`;
            formattedResult += `Security: ${result.requirements.security_level}\n`;
            formattedResult += `Performance: ${result.requirements.performance_priority}\n\n`;
            if (result.top_recommendation) {
                formattedResult += `🥇 TOP RECOMMENDATION:\n`;
                formattedResult += `${result.top_recommendation.algorithm} (Score: ${result.top_recommendation.score}/100)\n`;
                formattedResult += `Reason: ${result.top_recommendation.reason}\n\n`;
            }
            formattedResult += `📋 All Recommendations:\n`;
            result.recommendations.forEach((rec, index) => {
                formattedResult += `${index + 1}. ${rec.algorithm} (${rec.score}/100)\n`;
                formattedResult += `   Reason: ${rec.reason}\n`;
                if (rec.pros) formattedResult += `   Pros: ${rec.pros.join(', ')}\n`;
                if (rec.cons) formattedResult += `   Cons: ${rec.cons.join(', ')}\n\n`;
            });
            showResult('rec-result', formattedResult, false);
        } else {
            showError('rec-result', result.error || 'Failed to get recommendations');
        }
    } catch (error) {
        showLoading('rec-loading', false);
        showError('rec-result', 'Failed to get recommendations: ' + error.message);
    }
}