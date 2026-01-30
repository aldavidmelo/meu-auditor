from flask import Flask, request, jsonify
from flask_cors import CORS
import concurrent.futures
import titanium_auditor as auditor # Importa seu script original

app = Flask(__name__)
CORS(app)

@app.route('/audit', methods=['POST'])
def run_audit():
    data = request.json
    proxies = data.get('proxies', [])
    
    # Executa a auditoria usando a lógica do seu script original
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(auditor.audit_endpoint, proxies))
    
    return jsonify(results)

# Isso é necessário para a Hostinger rodar o app
application = app