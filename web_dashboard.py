#!/usr/bin/env python3
"""
Web Dashboard with Integrated API
"""
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
import os
from datetime import datetime
from dom_xss_scanner import DOMXSSScanner
from attack_tools import AttackToolsSuite

app = Flask(__name__)
CORS(app)

# Initialize scanners
dom_scanner = DOMXSSScanner()
attack_tools = AttackToolsSuite()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.get_json()
    target = data.get('target')
    scan_type = data.get('scanType', 'full')
    
    results = {
        'status': 'completed',
        'target': target,
        'scan_type': scan_type,
        'vulnerabilities': [],
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        if scan_type in ['full', 'xss']:
            dom_scanner.scan_url(target)
            results['vulnerabilities'].extend(dom_scanner.vulnerabilities)
        
        if scan_type in ['full', 'sql']:
            sql_vulns = attack_tools.sql_injection_scan(target)
            results['vulnerabilities'].extend(sql_vulns)
        
        results['count'] = len(results['vulnerabilities'])
        
    except Exception as e:
        results['status'] = 'error'
        results['error'] = str(e)
    
    return jsonify(results)

@app.route('/api/reports')
def get_reports():
    """Get all reports"""
    reports = []
    if os.path.exists('reports'):
        for file in sorted(os.listdir('reports'), reverse=True):
            if file.endswith('.json'):
                with open(f'reports/{file}') as f:
                    report = json.load(f)
                    reports.append({
                        'filename': file,
                        'date': report.get('scan_date', 'Unknown'),
                        'vulnerabilities': report.get('total_vulnerabilities', 0)
                    })
    return jsonify(reports)

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║   XSS Scanner Web Dashboard                      ║
    ║   http://localhost:5000                          ║
    ╚═══════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=5000, debug=True)
