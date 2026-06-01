from __future__ import annotations

from flask import Flask, request, jsonify, abort
import threading
import time
from typing import Dict

app = Flask(__name__)

# In-memory registry: app -> instanceId -> instance data
REGISTRY: Dict[str, Dict[str, dict]] = {}
REG_LOCK = threading.Lock()

@app.route('/eureka/apps', methods=['GET'])
def list_apps():
    with REG_LOCK:
        apps = []
        for app_name, instances in REGISTRY.items():
            apps.append({
                'name': app_name,
                'instance': list(instances.values())
            })
    return jsonify({'applications': {'application': apps}})

@app.route('/eureka/apps/<app_id>', methods=['GET'])
def get_app(app_id):
    app_key = app_id.upper()
    with REG_LOCK:
        instances = list(REGISTRY.get(app_key, {}).values())
    if not instances:
        return jsonify({'application': {}}), 404
    return jsonify({'application': {'name': app_key, 'instance': instances}})

@app.route('/eureka/apps/<app_id>', methods=['POST'])
def register_app(app_id):
    data = request.get_json(force=True)
    if not data or 'instance' not in data:
        abort(400)
    inst = data['instance']
    # Determine instanceId
    instance_id = inst.get('instanceId')
    port = None
    try:
        port = inst.get('port', {}).get('$')
    except Exception:
        port = None
    if not instance_id:
        host = inst.get('hostName') or inst.get('ipAddr') or 'unknown'
        if port:
            instance_id = f"{host}:{port}"
        else:
            instance_id = host
    inst['instanceId'] = instance_id
    inst['status'] = inst.get('status', 'UP')
    inst['lastUpdatedTimestamp'] = int(time.time() * 1000)
    with REG_LOCK:
        REGISTRY.setdefault(app_id.upper(), {})[instance_id] = inst
    return ('', 204)

@app.route('/eureka/apps/<app_id>/<instance_id>', methods=['PUT', 'DELETE'])
def heartbeat_or_delete(app_id, instance_id):
    app_key = app_id.upper()
    with REG_LOCK:
        if app_key not in REGISTRY:
            return ('', 404)

        # Direct match
        if instance_id in REGISTRY[app_key]:
            if request.method == 'PUT':
                REGISTRY[app_key][instance_id]['lastUpdatedTimestamp'] = int(time.time() * 1000)
                return ('', 200)
            else:
                del REGISTRY[app_key][instance_id]
                return ('', 200)

        # Try to match by port if instanceId differs (container hostname vs provided hostName)
        parts = instance_id.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            port = int(parts[1])
            for existing_id, inst in list(REGISTRY[app_key].items()):
                try:
                    inst_port = int(inst.get('port', {}).get('$') or 0)
                except Exception:
                    inst_port = 0
                if inst_port == port:
                    # Remap the instance under the new instance_id
                    inst['instanceId'] = instance_id
                    inst['lastUpdatedTimestamp'] = int(time.time() * 1000)
                    REGISTRY[app_key][instance_id] = inst
                    del REGISTRY[app_key][existing_id]
                    return ('', 200)

        return ('', 404)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8761)
