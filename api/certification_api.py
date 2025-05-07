from flask import Flask, request, jsonify
import datetime
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
from analysis.mcp_analysis_agent import MCPAnalysisAgent
from rq import Queue
from redis import Redis

app = Flask(__name__)
client = MongoClient(os.environ.get("MONGODB_URI", "mongodb://localhost:27017/"))
db = client["mcp_security"]

# Set up Redis queue for background processing
redis_conn = Redis()
q = Queue('mcp_analysis', connection=redis_conn)

@app.route('/api/certification/request', methods=['POST'])
def request_certification():
    """Request certification for a GitHub repository"""
    data = request.json
    repo_url = data.get('repo_url')
    contact_email = data.get('contact_email')
    
    # Validate inputs
    if not repo_url or not is_valid_github_url(repo_url):
        return jsonify({"error": "Invalid GitHub repository URL"}), 400
    
    # Check if we already have a recent analysis
    existing_analysis = db.repositories.find_one({
        "repo_url": repo_url,
        "evaluation_date": {"$gt": datetime.datetime.now() - datetime.timedelta(days=30)}
    })
    
    if existing_analysis:
        # Return existing certification status
        return jsonify({
            "status": "existing",
            "certification_level": existing_analysis.get("certification_level", "None"),
            "evaluation_date": existing_analysis.get("evaluation_date").isoformat()
        })
    
    # Queue new analysis
    job = q.enqueue(
        'tasks.analyze_repository',
        repo_url=repo_url,
        contact_email=contact_email,
        job_timeout='1h'
    )
    
    # Record the request
    db.certification_requests.insert_one({
        "repo_url": repo_url,
        "contact_email": contact_email,
        "request_date": datetime.datetime.now(),
        "job_id": str(job.id),
        "status": "queued"
    })
    
    return jsonify({
        "status": "queued",
        "job_id": str(job.id),
        "estimated_completion": "Your analysis will be completed within 24 hours"
    })

@app.route('/api/certification/status/<job_id>', methods=['GET'])
def check_certification_status(job_id):
    """Check the status of a certification request"""
    job = q.fetch_job(job_id)
    
    if not job:
        return jsonify({"error": "Job not found"}), 404
    
    status = {
        "job_id": job_id,
        "status": job.get_status(),
        "queue_position": get_queue_position(job_id),
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "ended_at": job.ended_at.isoformat() if job.ended_at else None
    }
    
    if job.is_finished:
        result = job.result
        if result and "certification_level" in result:
            status["certification_level"] = result["certification_level"]
    
    return jsonify(status)

def is_valid_github_url(url):
    """Validate that a URL is a GitHub repository URL"""
    import re
    pattern = r'^https://github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+/?$'
    return bool(re.match(pattern, url))

def get_queue_position(job_id):
    """Get the position of a job in the queue"""
    registry = q.started_job_registry
    if registry.contains(job_id):
        return 0
    
    # Check if job is in the queue
    for i, job in enumerate(q.get_jobs()):
        if job.id == job_id:
            return i + 1
    
    return None

    