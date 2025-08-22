// Universal Encryption Platform - Main JavaScript
// Shared functionality across all pages

// Global variables
let currentDataType = 'text';
let selectedAlgorithm = 'AES-256-GCM';
let lastEncryptionResult = null;

// Available algorithms for each data type
const algorithms = {
    text: [{
        name: 'AES-256-GCM',
        description: 'Industry standard with authentication',
        security: 'Very High',
        speed: 'Fast'
    }, {
        name: 'ChaCha20-Poly1305',
        description: 'Modern stream cipher',
        security: 'Very High',
        speed: 'Very Fast'
    }, {
        name: 'XChaCha20-Poly1305',
        description: 'Extended nonce stream cipher',
        security: 'Very High',
        speed: 'Very Fast'
    }, {
        name: 'RSA-4096',
        description: 'Public key encryption',
        security: 'Very High',
        speed: 'Slow'
    }, {
        name: 'FF1-AES',
        description: 'Format-preserving encryption',
        security: 'High',
        speed: 'Moderate'
    }, {
        name: 'Kyber-768',
        description: 'Post-quantum secure',
        security: 'Quantum Resistant',
        speed: 'Fast'
    }, {
        name: 'Caesar',
        description: 'Educational cipher',
        security: 'Educational',
        speed: 'Very Fast',
        requiresPassword: false
    }, {
        name: 'Enigma',
        description: 'Historical rotor cipher',
        security: 'Educational',
        speed: 'Fast',
        requiresPassword: false
    }],
    image: [{
        name: 'AES-256-CBC',
        description: 'Block cipher for images',
        security: 'Very High',
        speed: 'Fast'
    }, {
        name: 'AES-256-GCM',
        description: 'Authenticated encryption',
        security: 'Very High',
        speed: 'Fast'
    }, {
        name: 'ChaCha20-Poly1305',
        description: 'Stream cipher for images',
        security: 'Very High',
        speed: 'Very Fast'
    }],
    file: [{
        name: 'AES-256-GCM',
        description: 'General file encryption',
        security: 'Very High',
        speed: 'Fast'
    }, {
        name: 'XChaCha20-Poly1305',
        description: 'Extended nonce encryption',
        security: 'Very High',
        speed: 'Very Fast'
    }, {
        name: 'AES-256-XTS',
        description: 'Full disk encryption standard',
        security: 'Very High',
        speed: 'Fast'
    }, {
        name: 'ChaCha20-Poly1305',
        description: 'Modern file encryption',
        security: 'Very High',
        speed: 'Very Fast'
    }]
};

// Navigation functions
function showSection(sectionId) {
    document.querySelectorAll('.content-section').forEach(section => section.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    const selectedSection = document.getElementById(sectionId);
    if (selectedSection) {
        selectedSection.classList.add('active');
    }
    if (event && event.target) {
        event.target.classList.add('active');
    }
}

// Algorithm selection
function selectAlgorithm(algorithmName, dataType) {
    selectedAlgorithm = algorithmName;
    currentDataType = dataType;
    const container = document.getElementById(`${dataType}-algorithms`);
    if (container) {
        container.querySelectorAll('.algorithm-card').forEach(card => card.classList.remove('selected'));
        const selectedCard = Array.from(container.querySelectorAll('.algorithm-card')).find(card =>
            card.querySelector('h4').textContent === algorithmName
        );
        if (selectedCard) selectedCard.classList.add('selected');
    }
    
    // Show/hide password field based on algorithm requirements
    const algorithm = algorithms[dataType]?.find(alg => alg.name === algorithmName);
    const passwordField = document.getElementById(`${dataType}-password`);
    const passwordLabel = passwordField?.previousElementSibling;
    
    if (algorithm && algorithm.requiresPassword === false) {
        // Hide password field for algorithms that don't need it
        if (passwordField) passwordField.style.display = 'none';
        if (passwordLabel) passwordLabel.style.display = 'none';
    } else {
        // Show password field for algorithms that need it
        if (passwordField) passwordField.style.display = 'block';
        if (passwordLabel) passwordLabel.style.display = 'block';
    }
}

// Load algorithms into containers
function loadAlgorithms() {
    const textContainer = document.getElementById('text-algorithms');
    if (textContainer && algorithms.text) {
        textContainer.innerHTML = algorithms.text.map((algo, index) => `
            <div class="algorithm-card ${index === 0 ? 'selected' : ''}" onclick="selectAlgorithm('${algo.name}', 'text')">
                <h4>${algo.name}</h4>
                <p>${algo.description}</p>
                <span class="algorithm-badge">${algo.security}</span>
                <span class="algorithm-badge">${algo.speed}</span>
            </div>
        `).join('');
    }
    const fileContainer = document.getElementById('file-algorithms');
    if (fileContainer && algorithms.file) {
        fileContainer.innerHTML = algorithms.file.map((algo, index) => `
            <div class="algorithm-card ${index === 0 ? 'selected' : ''}" onclick="selectAlgorithm('${algo.name}', 'file')">
                <h4>${algo.name}</h4>
                <p>${algo.description}</p>
                <span class="algorithm-badge">${algo.security}</span>
                <span class="algorithm-badge">${algo.speed}</span>
            </div>
        `).join('');
    }
}

// Result display functions
function showResult(resultId, content, isNew = true) {
    const element = document.getElementById(resultId);
    // Try multiple possible content element IDs
    let contentElement = document.getElementById(resultId + '-content') || 
                        document.getElementById(resultId.replace('-result', '-content')) ||
                        document.getElementById(resultId.replace('-result', '-result-content'));
    
    if (element && contentElement) {
        let displayContent = (typeof content === 'object') ? JSON.stringify(content, null, 2) : content;
        if (resultId === 'decrypt-result' && typeof content === 'string' && content.includes('Decrypted Text:')) {
            contentElement.innerHTML = `<div style="background: #d4edda; padding: 15px; border-radius: 8px; margin: 10px 0;">
                <h5 style="color: #155724; margin: 0 0 10px 0;">✅ Decryption Successful!</h5>
                <div style="background: white; padding: 10px; border-radius: 4px; border-left: 4px solid #28a745;">
                    <strong>Decrypted Message:</strong><br>
                    <span style="font-size: 16px; color: #333;">${content.split('Decrypted Text:')[1].trim()}</span>
                </div>
            </div>`;
        } else {
            contentElement.textContent = displayContent;
        }
        element.style.display = 'block';
        element.className = 'result-area success';
        addResultButtons(element, displayContent, resultId);
    }
}

function showError(resultId, message) {
    const element = document.getElementById(resultId);
    // Try multiple possible content element IDs
    let contentElement = document.getElementById(resultId + '-content') || 
                        document.getElementById(resultId.replace('-result', '-content')) ||
                        document.getElementById(resultId.replace('-result', '-result-content'));
    
    if (element && contentElement) {
        let enhancedMessage = message;
        if (message.includes('Missing required metadata')) {
            enhancedMessage += '\n\n💡 How to fix:\n' +
                '• Copy the complete metadata JSON from your encryption result\n' +
                '• Make sure all required fields are present\n' +
                '• For Enigma: ensure the metadata contains "configuration" field\n' +
                '• Check JSON formatting (use a validator if needed)';
        } else if (message.includes('Invalid metadata JSON')) {
            enhancedMessage += '\n\n💡 How to fix:\n' +
                '• Check for missing quotes around field names\n' +
                '• Remove any trailing commas\n' +
                '• Copy metadata exactly as provided';
        } else if (message.includes('405') || message.includes('Method Not Allowed')) {
            enhancedMessage = 'Feature temporarily unavailable. Please try the basic encryption/decryption features.';
        }
        contentElement.textContent = enhancedMessage;
        element.style.display = 'block';
        element.className = 'result-area error';
    }
}

// Add useful buttons to results
function addResultButtons(element, content, resultId) {
    const existingButtons = element.querySelectorAll('.result-btn');
    existingButtons.forEach(btn => btn.remove());
    
    // Get the actual content from the content element (for accurate copying)
    const contentElement = document.getElementById(resultId + '-content') || 
                          document.getElementById(resultId.replace('-result', '-content')) ||
                          document.getElementById(resultId.replace('-result', '-result-content'));
    const actualContent = contentElement ? contentElement.textContent : content;
    
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn btn-secondary result-btn';
    copyBtn.style.marginTop = '10px';
    copyBtn.style.marginRight = '10px';
    copyBtn.textContent = '📋 Copy';
    copyBtn.onclick = () => copyToClipboard(actualContent);
    element.appendChild(copyBtn);
    
    if (resultId === 'text-result' && lastEncryptionResult) {
        const quickDecryptBtn = document.createElement('button');
        quickDecryptBtn.className = 'btn result-btn';
        quickDecryptBtn.style.marginTop = '10px';
        quickDecryptBtn.textContent = '🔓 Quick Decrypt';
        quickDecryptBtn.onclick = quickDecrypt;
        element.appendChild(quickDecryptBtn);
    }
    if (resultId === 'files-result') {
        const refreshBtn = document.createElement('button');
        refreshBtn.className = 'btn btn-secondary result-btn';
        refreshBtn.style.marginTop = '10px';
        refreshBtn.textContent = '🔄 Refresh';
        refreshBtn.onclick = listFiles;
        element.appendChild(refreshBtn);
    }
}

// Loading states
function showLoading(loadingId, show) {
    const element = document.getElementById(loadingId);
    if (element) {
        element.style.display = show ? 'block' : 'none';
        if (show) {
            let dots = 0;
            const interval = setInterval(() => {
                dots = (dots + 1) % 4;
                element.textContent = 'Loading' + '.'.repeat(dots);
                if (element.style.display === 'none') clearInterval(interval);
            }, 500);
        }
    }
}

function hideElement(elementId) {
    const element = document.getElementById(elementId);
    if (element) element.style.display = 'none';
}

// Utility functions
function copyToClipboard(text) {
    if (typeof text === 'object') text = JSON.stringify(text, null, 2);
    navigator.clipboard.writeText(text).then(() => {
        const msgDiv = document.createElement('div');
        msgDiv.textContent = 'Copied to clipboard!';
        msgDiv.style.cssText = 'position:fixed; top:20px; right:20px; background:#28a745; color:white; padding:10px 15px; border-radius:5px; z-index:1001;';
        document.body.appendChild(msgDiv);
        setTimeout(() => document.body.removeChild(msgDiv), 2000);
    });
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function clearResults() {
    hideElement('text-result');
    const textInput = document.getElementById('text-input');
    const textPassword = document.getElementById('text-password');
    if (textInput) textInput.value = 'Hello World! This is a test message.';
    if (textPassword) textPassword.value = '';
}

// Update password field visibility for decrypt form
function updateDecryptPasswordField() {
    const algorithm = document.getElementById('decrypt-algorithm').value;
    const passwordField = document.getElementById('decrypt-password');
    const passwordLabel = passwordField?.previousElementSibling;
    
    // Check if algorithm requires password (check all data types for the algorithm)
    let requiresPassword = true;
    for (const dataType in algorithms) {
        const alg = algorithms[dataType].find(a => a.name === algorithm);
        if (alg && alg.requiresPassword === false) {
            requiresPassword = false;
            break;
        }
    }
    
    if (!requiresPassword) {
        // Hide password field for algorithms that don't need it
        if (passwordField) passwordField.style.display = 'none';
        if (passwordLabel) passwordLabel.style.display = 'none';
    } else {
        // Show password field for algorithms that need it
        if (passwordField) passwordField.style.display = 'block';
        if (passwordLabel) passwordLabel.style.display = 'block';
    }
}

// Quick decrypt functionality
function populateDecryptForm(result) {
    if (result && result.encrypted_data && result.metadata) {
        const decryptData = document.getElementById('decrypt-data-input');
        const decryptAlgo = document.getElementById('decrypt-algorithm');
        const decryptMeta = document.getElementById('decrypt-metadata');
        
        if (decryptData) decryptData.value = result.encrypted_data;
        if (decryptAlgo) decryptAlgo.value = result.metadata.algorithm;
        if (decryptMeta) decryptMeta.value = JSON.stringify(result.metadata, null, 2);
    }
}

function quickDecrypt() {
    if (!lastEncryptionResult) {
        showError('text-result', 'No recent encryption to decrypt.');
        return;
    }
    showSection('decrypt-data');
    populateDecryptForm(lastEncryptionResult);
    const decryptPassword = document.getElementById('decrypt-password');
    const textPassword = document.getElementById('text-password');
    if (decryptPassword && textPassword) {
        decryptPassword.value = textPassword.value;
    }
}

// File handling
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) displayFileInfo(file);
}

function handleDragOver(event) {
    event.preventDefault();
    event.currentTarget.classList.add('dragover');
}

function handleDrop(event) {
    event.preventDefault();
    event.currentTarget.classList.remove('dragover');
    const files = event.dataTransfer.files;
    if (files.length > 0) {
        const fileInput = document.getElementById('file-input');
        if (fileInput) {
            fileInput.files = files;
            displayFileInfo(files[0]);
        }
    }
}

function handleDragLeave(event) {
    event.currentTarget.classList.remove('dragover');
}

function displayFileInfo(file) {
    const fileDetails = document.getElementById('file-details');
    const fileInfo = document.getElementById('file-info');
    if (fileDetails && fileInfo) {
        fileDetails.innerHTML = `<strong>Name:</strong> ${file.name}<br><strong>Size:</strong> ${formatBytes(file.size)}`;
        fileInfo.style.display = 'block';
    }
}

// Setup event listeners
function setupEventListeners() {
    const dropZone = document.querySelector('.file-drop-zone');
    if (dropZone) {
        dropZone.addEventListener('dragover', handleDragOver);
        dropZone.addEventListener('drop', handleDrop);
        dropZone.addEventListener('dragleave', handleDragLeave);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    setupEventListeners();
    loadAlgorithms();
    
    // Initialize password field visibility for decrypt form
    if (document.getElementById('decrypt-algorithm')) {
        updateDecryptPasswordField();
    }
    
    // Animate stat numbers on home page
    const statNumbers = document.querySelectorAll('.stat-number');
    statNumbers.forEach(stat => {
        const finalValue = stat.textContent;
        if (!isNaN(finalValue)) {
            let currentValue = 0;
            const increment = finalValue / 20;
            const timer = setInterval(() => {
                currentValue += increment;
                if (currentValue >= finalValue) {
                    stat.textContent = finalValue;
                    clearInterval(timer);
                } else {
                    stat.textContent = Math.floor(currentValue);
                }
            }, 50);
        }
    });
    
    // Add hover effects to feature cards
    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.background = 'rgba(255, 255, 255, 1)';
        });
        card.addEventListener('mouseleave', function() {
            this.style.background = 'rgba(255, 255, 255, 0.95)';
        });
    });
});