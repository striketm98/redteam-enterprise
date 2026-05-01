from flask import Blueprint, request, jsonify
from core.task_runner import TaskRunner
from core.cred_engine import CredentialEngine
from core.decision_engine import DecisionEngine
import json

api = Blueprint("api", __name__)
task_runner = TaskRunner()
cred_engine = CredentialEngine()
decision_engine = DecisionEngine()

# Store targets in memory (in production, use database)
targets = []
findings = []

@api.route("/stats", methods=["GET"])
def get_stats():
    """Get framework statistics"""
    return jsonify({
        "targets": len(targets),
        "credentials": len(cred_engine.credentials),
        "vulnerabilities": len(findings),
        "success_rate": 75  # Placeholder
    })

@api.route("/targets", methods=["GET"])
def get_targets():
    """Get all targets"""
    return jsonify(targets)

@api.route("/targets", methods=["POST"])
def add_target():
    """Add a new target"""
    data = request.json
    target = {
        "id": len(targets) + 1,
        "address": data.get("address"),
        "status": "pending",
        "ports": [],
        "services": [],
        "created": __import__('datetime').datetime.now().isoformat()
    }
    targets.append(target)
    return jsonify(target), 201

@api.route("/scan", methods=["POST"])
def scan_target():
    """Scan a target"""
    data = request.json
    target = data.get("target")
    
    # Update decision context
    decision_engine.update_context({
        "target": target,
        "ports": [80, 443, 22, 445],  # Placeholder - would be from actual scan
        "foothold": False
    })
    
    # Get decision
    decision = decision_engine.decide()
    
    return jsonify({
        "target": target,
        "decision": decision,
        "status": "scan_completed"
    })

@api.route("/credentials", methods=["GET"])
def get_credentials():
    """Get discovered credentials"""
    return jsonify(cred_engine.credentials)

@api.route("/credentials", methods=["POST"])
def add_credential():
    """Add a credential"""
    data = request.json
    cred = cred_engine.add_credential(
        data.get("username"),
        data.get("password"),
        data.get("source", "manual")
    )
    return jsonify(cred), 201

@api.route("/decision", methods=["POST"])
def get_decision():
    """Get next action decision"""
    context = request.json
    decision = decision_engine.decide(context)
    return jsonify(decision)

@api.route("/execute", methods=["POST"])
async def execute_command():
    """Execute a command"""
    data = request.json
    command = data.get("command")
    
    # Run command asynchronously
    result = await task_runner.run_command(command)
    return jsonify(result)

@api.route("/findings", methods=["GET"])
def get_findings():
    """Get all findings"""
    return jsonify(findings)

@api.route("/findings", methods=["POST"])
def add_finding():
    """Add a finding"""
    data = request.json
    finding = {
        "id": len(findings) + 1,
        "title": data.get("title"),
        "description": data.get("description"),
        "severity": data.get("severity", "medium"),
        "timestamp": __import__('datetime').datetime.now().isoformat()
    }
    findings.append(finding)
    return jsonify(finding), 201

@api.route("/export", methods=["GET"])
def export_data():
    """Export all data"""
    export_data = {
        "targets": targets,
        "credentials": cred_engine.credentials,
        "findings": findings,
        "export_date": __import__('datetime').datetime.now().isoformat()
    }
    return jsonify(export_data)