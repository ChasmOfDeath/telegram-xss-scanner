#!/usr/bin/env python3
"""
REST API Server for XSS Scanner
Provides programmatic access to all scanner features
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
from datetime import datetime
from dom_xss_scanner import DOMXSSScanner
from attack_tools import AttackToolsSuite

app = Flask(__name__)
CORS(app)  # Enable CORS for external access

# Initialize scanners
dom_scanner = DOMXSSScanner()
attack_tools = AttackToolsSuite()

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/v1/scan/xss', methods=['POST'])
def scan_xss():
    """Scan for XSS vulnerabilities"""
    data = request.get_json()
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target URL required'}), 400
    
    # Run scan
    dom_scanner.scan_url(target)
    
    return jsonify({
        'status': 'completed',
        'target': target,
        'vulnerabilities': dom_scanner.vulnerabilities,
        'count': len(dom_scanner.vulnerabilities)
    })

@app.route('/api/v1/scan/sql', methods=['POST'])
def scan_sql():
    """Scan for SQL injection"""
    data = request.get_json()
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target URL required'}), 400
    
    vulns = attack_tools.sql_injection_scan(target)
    
    return jsonify({
        'status': 'completed',
        'target': target,
        'vulnerabilities': vulns,
        'count': len(vulns)
    })

@app.route('/api/v1/reports', methods=['GET'])
def list_reports():
    """List all scan reports"""
    reports = []
    
    if os.path.exists('reports'):
        for file in os.listdir('reports'):
            if file.endswith('.json'):
                reports.append({
                    'filename': file,
                    'path': f'/api/v1/reports/{file}'
                })
    
    return jsonify({'reports': reports, 'count': len(reports)})

@app.route('/api/v1/reports/<filename>', methods=['GET'])
def get_report(filename):
    """Get specific report"""
    filepath = f'reports/{filename}'
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'Report not found'}), 404
    
    with open(filepath) as f:
        report = json.load(f)
    
    return jsonify(report)

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║   XSS Scanner REST API Server                    ║
    ║   Running on http://localhost:8000               ║
    ╚═══════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=8000, debug=True)
