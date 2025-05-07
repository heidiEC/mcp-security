import sys
import os
import certifi

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymongo import MongoClient
from config import MONGODB_URI, MONGODB_DB_NAME

def init_database():
    """Initialize the MongoDB database with required collections and indexes"""
    client = MongoClient(MONGODB_URI, tlsCAFile=certifi.where())
    db = client[MONGODB_DB_NAME]
    
    # Create collections if they don't exist
    if "repositories" not in db.list_collection_names():
        db.create_collection("repositories")
        print("Created 'repositories' collection")
        
        # Create indexes
        db.repositories.create_index("repo_url", unique=True)
        print("Created index on repositories.repo_url")
    
    if "security_profiles" not in db.list_collection_names():
        db.create_collection("security_profiles")
        print("Created 'security_profiles' collection")
        
        # Create indexes
        db.security_profiles.create_index("repo_id")
        print("Created index on security_profiles.repo_id")
    
    if "security_files" not in db.list_collection_names():
        db.create_collection("security_files")
        print("Created 'security_files' collection")
        
        # Create indexes
        db.security_files.create_index([("repo_id", 1), ("file_path", 1)], unique=True)
        print("Created compound index on security_files.repo_id and file_path")
    
    if "certification_history" not in db.list_collection_names():
        db.create_collection("certification_history")
        print("Created 'certification_history' collection")
        
        # Create indexes
        db.certification_history.create_index("repo_id")
        print("Created index on certification_history.repo_id")
    
    if "certification_requests" not in db.list_collection_names():
        db.create_collection("certification_requests")
        print("Created 'certification_requests' collection")
        
        # Create indexes
        db.certification_requests.create_index("repo_url")
        db.certification_requests.create_index("job_id", unique=True)
        print("Created indexes on certification_requests")
    
    print(f"Database '{MONGODB_DB_NAME}' initialized successfully!")

if __name__ == "__main__":
    init_database()