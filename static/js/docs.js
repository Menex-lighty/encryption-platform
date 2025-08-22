// Documentation Page JavaScript
// Interactive API testing functionality

// Test endpoint function for GET requests
async function testEndpoint(endpoint) {
    try {
        const response = await fetch(endpoint);
        const data = await response.json();
        
        // Create modal to show results
        showResultModal(endpoint, data);
    } catch (error) {
        alert('Error testing endpoint: ' + error.message);
    }
}

// Interactive API tester for POST requests
function openApiTester(endpoint, method = 'GET') {
    let formContent = '';
    
    if (endpoint === '/api/encrypt') {
        formContent = `
            <div class="mb-3">
                <label class="form-label">Text to Encrypt:</label>
                <textarea class="form-control" id="encrypt-data" rows="3" placeholder="Hello World!">Hello World!</textarea>
            </div>
            <div class="mb-3">
                <label class="form-label">Algorithm:</label>
                <select class="form-control" id="encrypt-algorithm">
                    <option value="AES-256-GCM">AES-256-GCM</option>
                    <option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option>
                    <option value="XChaCha20-Poly1305">XChaCha20-Poly1305</option>
                    <option value="RSA-4096">RSA-4096</option>
                    <option value="FF1-AES">FF1-AES</option>
                    <option value="Caesar">Caesar</option>
                    <option value="Enigma">Enigma</option>
                    <option value="Kyber-768">Kyber-768</option>
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label">Password:</label>
                <input type="password" class="form-control" id="encrypt-password" placeholder="Enter password">
            </div>
        `;
    } else if (endpoint === '/api/decrypt') {
        formContent = `
            <div class="mb-3">
                <label class="form-label">Encrypted Data:</label>
                <textarea class="form-control" id="decrypt-data" rows="3" placeholder="Paste encrypted data here..."></textarea>
            </div>
            <div class="mb-3">
                <label class="form-label">Algorithm:</label>
                <select class="form-control" id="decrypt-algorithm">
                    <option value="AES-256-GCM">AES-256-GCM</option>
                    <option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option>
                    <option value="XChaCha20-Poly1305">XChaCha20-Poly1305</option>
                    <option value="RSA-4096">RSA-4096</option>
                    <option value="FF1-AES">FF1-AES</option>
                    <option value="Caesar">Caesar</option>
                    <option value="Enigma">Enigma</option>
                    <option value="Kyber-768">Kyber-768</option>
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label">Password:</label>
                <input type="password" class="form-control" id="decrypt-password" placeholder="Enter password">
            </div>
            <div class="mb-3">
                <label class="form-label">Metadata (JSON):</label>
                <textarea class="form-control" id="decrypt-metadata" rows="4" placeholder='{"iv":"...","tag":"...","salt":"..."}'></textarea>
            </div>
        `;
    } else if (endpoint === '/api/algorithms/compare') {
        formContent = `
            <div class="mb-3">
                <label class="form-label">Select Algorithms to Compare:</label>
                <div>
                    <input type="checkbox" id="compare-aes" value="AES-256-GCM" checked> <label for="compare-aes">AES-256-GCM</label><br>
                    <input type="checkbox" id="compare-chacha" value="ChaCha20-Poly1305" checked> <label for="compare-chacha">ChaCha20-Poly1305</label><br>
                    <input type="checkbox" id="compare-xchacha" value="XChaCha20-Poly1305"> <label for="compare-xchacha">XChaCha20-Poly1305</label><br>
                    <input type="checkbox" id="compare-rsa" value="RSA-4096"> <label for="compare-rsa">RSA-4096</label><br>
                    <input type="checkbox" id="compare-ff1" value="FF1-AES"> <label for="compare-ff1">FF1-AES</label><br>
                    <input type="checkbox" id="compare-caesar" value="Caesar"> <label for="compare-caesar">Caesar</label><br>
                    <input type="checkbox" id="compare-enigma" value="Enigma"> <label for="compare-enigma">Enigma</label><br>
                    <input type="checkbox" id="compare-kyber" value="Kyber-768"> <label for="compare-kyber">Kyber-768</label>
                </div>
            </div>
            <div class="mb-3">
                <label class="form-label">Data Type:</label>
                <select class="form-control" id="compare-datatype">
                    <option value="text">Text</option>
                    <option value="file">File</option>
                </select>
            </div>
        `;
    } else if (endpoint === '/api/algorithms/recommend') {
        formContent = `
            <div class="mb-3">
                <label class="form-label">Data Type:</label>
                <select class="form-control" id="rec-datatype">
                    <option value="text">Text</option>
                    <option value="file">File</option>
                    <option value="image">Image</option>
                    <option value="postquantum">Post-Quantum</option>
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label">Security Level:</label>
                <select class="form-control" id="rec-security">
                    <option value="high">High</option>
                    <option value="very_high">Very High</option>
                    <option value="educational">Educational</option>
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label">Performance Priority:</label>
                <select class="form-control" id="rec-performance">
                    <option value="balanced">Balanced</option>
                    <option value="high">High Performance</option>
                    <option value="security">Security First</option>
                </select>
            </div>
        `;
    } else if (endpoint === '/api/test/encryption') {
        formContent = `
            <div class="mb-3">
                <label class="form-label">Algorithm to Test:</label>
                <select class="form-control" id="test-algorithm">
                    <option value="AES-256-GCM">AES-256-GCM</option>
                    <option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option>
                    <option value="XChaCha20-Poly1305">XChaCha20-Poly1305</option>
                    <option value="FF1-AES">FF1-AES</option>
                    <option value="Caesar">Caesar</option>
                    <option value="Enigma">Enigma</option>
                    <option value="Kyber-768">Kyber-768</option>
                </select>
            </div>
        `;
    }

    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Test API: ${method} ${endpoint}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    ${formContent}
                    <div id="api-result" style="display: none;">
                        <hr>
                        <h6>Response:</h6>
                        <pre id="api-response" style="background: #f8f9fa; padding: 15px; border-radius: 5px; max-height: 300px; overflow-y: auto;"></pre>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-primary" onclick="executeApiTest('${endpoint}', '${method}')">Execute Test</button>
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
    
    modal.addEventListener('hidden.bs.modal', () => {
        document.body.removeChild(modal);
    });
}

// Execute API test
async function executeApiTest(endpoint, method) {
    const resultDiv = document.getElementById('api-result');
    const responseDiv = document.getElementById('api-response');
    
    try {
        let requestBody = null;
        const headers = { 'Content-Type': 'application/json' };
        
        if (method === 'POST') {
            if (endpoint === '/api/encrypt') {
                requestBody = {
                    data: document.getElementById('encrypt-data').value,
                    algorithm: document.getElementById('encrypt-algorithm').value,
                    password: document.getElementById('encrypt-password').value
                };
            } else if (endpoint === '/api/decrypt') {
                requestBody = {
                    encrypted_data: document.getElementById('decrypt-data').value,
                    algorithm: document.getElementById('decrypt-algorithm').value,
                    password: document.getElementById('decrypt-password').value,
                    metadata: JSON.parse(document.getElementById('decrypt-metadata').value || '{}')
                };
            } else if (endpoint === '/api/algorithms/compare') {
                const algorithms = [];
                document.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
                    algorithms.push(cb.value);
                });
                requestBody = {
                    algorithms: algorithms,
                    data_type: document.getElementById('compare-datatype').value
                };
            } else if (endpoint === '/api/algorithms/recommend') {
                requestBody = {
                    data_type: document.getElementById('rec-datatype').value,
                    security_level: document.getElementById('rec-security').value,
                    performance_priority: document.getElementById('rec-performance').value,
                    use_case: 'general'
                };
            } else if (endpoint === '/api/test/encryption') {
                requestBody = {
                    algorithm: document.getElementById('test-algorithm').value
                };
            }
        }

        const config = {
            method: method,
            headers: headers
        };

        if (requestBody) {
            config.body = JSON.stringify(requestBody);
        }

        const response = await fetch(endpoint, config);
        const data = await response.json();
        
        responseDiv.textContent = JSON.stringify(data, null, 2);
        resultDiv.style.display = 'block';
        
    } catch (error) {
        responseDiv.textContent = 'Error: ' + error.message;
        resultDiv.style.display = 'block';
    }
}

// Simple API testers for specific endpoints
function testSystemStatus() {
    testEndpoint('/api/system/status');
}

function testFilesList() {
    testEndpoint('/api/files');
}

function testFileDownload() {
    const fileId = prompt('Enter File ID:');
    const password = prompt('Enter Password:');
    if (fileId && password) {
        window.open(`/api/download/${fileId}?password=${encodeURIComponent(password)}`, '_blank');
    }
}

function testFileDelete() {
    const fileId = prompt('Enter File ID to delete:');
    if (fileId && confirm(`Are you sure you want to delete file ${fileId}?`)) {
        fetch(`/api/files/${fileId}`, { method: 'DELETE' })
            .then(response => response.json())
            .then(data => showResultModal(`DELETE /api/files/${fileId}`, data))
            .catch(error => alert('Error: ' + error.message));
    }
}

function showResultModal(endpoint, data) {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">API Response: ${endpoint}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <pre><code class="language-json">${JSON.stringify(data, null, 2)}</code></pre>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
    
    // Clean up when modal is hidden
    modal.addEventListener('hidden.bs.modal', () => {
        document.body.removeChild(modal);
    });
}

// Smooth scrolling for navigation links
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.docs-nav .nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const target = document.querySelector(targetId);
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
                // Also update URL hash
                if(history.pushState) {
                    history.pushState(null, null, targetId);
                } else {
                    location.hash = targetId;
                }
            }
        });
    });
    
    // Highlight current section in navigation on scroll
    window.addEventListener('scroll', () => {
        const sections = document.querySelectorAll('section[id]');
        const navLinks = document.querySelectorAll('.docs-nav .nav-link');
        
        let currentSection = '';
        sections.forEach(section => {
            const rect = section.getBoundingClientRect();
            if (rect.top <= 100 && rect.bottom >= 100) {
                currentSection = section.id;
            }
        });
        
        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === '#' + currentSection) {
                link.classList.add('active');
            }
        });
    });
});