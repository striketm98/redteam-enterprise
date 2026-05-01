from flask import Flask, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'redteam-secret-key-2024')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Import modules
from api.routes import api
from core.decision_engine import DecisionEngine
from core.cred_engine import CredentialEngine
from core.privesc_engine import PrivEscEngine
from core.exploit_matcher import ExploitMatcher
from core.task_runner import TaskRunner
from graph.neo4j_client import Neo4jClient, GraphAnalyzer
from lab.deployer import LabDeployer
from report.generator import ReportGenerator

# Initialize components
decision_engine = DecisionEngine()
cred_engine = CredentialEngine()
privesc_engine = PrivEscEngine()
exploit_matcher = ExploitMatcher()
task_runner = TaskRunner()
graph_client = Neo4jClient()
graph_analyzer = GraphAnalyzer(graph_client)
lab_deployer = LabDeployer()
report_generator = ReportGenerator()

# Register blueprints
app.register_blueprint(api, url_prefix='/api')

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    socketio.emit('connected', {'status': 'Connected to Red Team Framework'})

@socketio.on('execute_command')
def handle_command(data):
    import asyncio
    command = data.get('command', '')
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(task_runner.run_command(command))
    socketio.emit('command_result', result)

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     RED TEAM ENTERPRISE FRAMEWORK - PROFESSIONAL EDITION   ║
    ║                                                            ║
    ║  Access: http://localhost:5000                            ║
    ║  API: http://localhost:5000/api                           ║
    ║                                                            ║
    ║  Features:                                                ║
    ║  - Decision Intelligence Engine                          ║
    ║  - Attack Graph Analysis                                 ║
    ║  - Credential Reuse Intelligence                         ║
    ║  - Privilege Escalation Detection                        ║
    ║  - Lab Orchestration                                     ║
    ║  - Professional Reporting                                ║
    ║                                                            ║
    ║  ⚠️  Educational Purpose Only                            ║
    ║  ⚠️  Use only in authorized environments                 ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)