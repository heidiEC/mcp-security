// MongoDB schema definitions for MCP Security Certification Program

// Repository collection - stores basic information about MCP repositories
db.createCollection("repositories", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["name", "repo_url", "evaluation_date", "last_updated"],
      properties: {
        name: {
          bsonType: "string",
          description: "Name of the MCP server implementation"
        },
        repo_url: {
          bsonType: "string",
          description: "URL to the GitHub repository"
        },
        primary_function: {
          bsonType: "string",
          description: "Primary function (Memory/Retrieval/Tool/etc.)"
        },
        evaluation_date: {
          bsonType: "date",
          description: "Date of the most recent evaluation"
        },
        evaluator: {
          bsonType: "string",
          description: "Name of the evaluator (human or AI)"
        },
        version_evaluated: {
          bsonType: "string",
          description: "Version or commit hash evaluated"
        },
        certification_level: {
          bsonType: "string",
          enum: ["None", "Bronze", "Silver", "Gold"],
          description: "Current certification level"
        },
        last_updated: {
          bsonType: "date",
          description: "Date the repository was last updated"
        }
      }
    }
  }
});

// SecurityProfiles collection - stores detailed security evaluations
db.createCollection("security_profiles", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["repo_id", "evaluation_date", "scores", "executive_summary"],
      properties: {
        repo_id: {
          bsonType: "objectId",
          description: "Reference to the repository"
        },
        evaluation_date: {
          bsonType: "date",
          description: "Date of evaluation"
        },
        evaluator: {
          bsonType: "string",
          description: "Name of evaluator"
        },
        scores: {
          bsonType: "object",
          required: ["overall", "authentication", "data_protection", "input_validation", "prompt_security", "infrastructure"],
          properties: {
            overall: {
              bsonType: "number",
              minimum: 1,
              maximum: 10,
              description: "Overall security score (1-10)"
            },
            authentication: {
              bsonType: "number",
              minimum: 1,
              maximum: 10,
              description: "Authentication & Authorization score (1-10)"
            },
            data_protection: {
              bsonType: "number",
              minimum: 1,
              maximum: 10,
              description: "Data Protection score (1-10)"
            },
            input_validation: {
              bsonType: "number",
              minimum: 1,
              maximum: 10,
              description: "Input Validation score (1-10)"
            },
            prompt_security: {
              bsonType: "number",
              minimum: 1,
              maximum: 10,
              description: "Prompt Security score (1-10)"
            },
            infrastructure: {
              bsonType: "number",
              minimum: 1,
              maximum: 10,
              description: "Infrastructure Security score (1-10)"
            }
          }
        },
        executive_summary: {
          bsonType: "string",
          description: "Summary of security posture"
        },
        security_features: {
          bsonType: "object",
          properties: {
            authentication: { bsonType: "object" },
            authorization: { bsonType: "object" },
            data_protection: { bsonType: "object" },
            input_validation: { bsonType: "object" },
            prompt_security: { bsonType: "object" },
            infrastructure: { bsonType: "object" }
          }
        },
        vulnerabilities: {
          bsonType: "array",
          items: {
            bsonType: "object",
            required: ["severity", "category", "description", "recommendation"],
            properties: {
              id: { bsonType: "string" },
              severity: { 
                bsonType: "string",
                enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
              },
              category: { bsonType: "string" },
              description: { bsonType: "string" },
              recommendation: { bsonType: "string" },
              status: { 
                bsonType: "string",
                enum: ["Open", "Fixed", "In Progress", "Won't Fix"]
              }
            }
          }
        },
        deployment_recommendations: { bsonType: "string" },
        code_quality: { bsonType: "object" },
        certification: {
          bsonType: "object",
          required: ["level", "justification"],
          properties: {
            level: { 
              bsonType: "string",
              enum: ["None", "Bronze", "Silver", "Gold"]
            },
            justification: { bsonType: "string" },
            conditions: { bsonType: "string" },
            expiration: { bsonType: "date" }
          }
        },
        markdown_report: {
          bsonType: "string",
          description: "Full markdown report"
        }
      }
    }
  }
});

// SecurityFiles collection - stores security-relevant files from repositories
db.createCollection("security_files", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["repo_id", "file_path", "content", "file_type"],
      properties: {
        repo_id: {
          bsonType: "objectId",
          description: "Reference to the repository"
        },
        file_path: {
          bsonType: "string",
          description: "Path to the file within the repository"
        },
        file_type: {
          bsonType: "string",
          enum: ["config", "auth", "api", "main", "docs", "dependencies"],
          description: "Type of security-relevant file"
        },
        content: {
          bsonType: "string",
          description: "Content of the file"
        },
        last_updated: {
          bsonType: "date",
          description: "Last update timestamp"
        }
      }
    }
  }
});

// CertificationHistory collection - tracks certification changes over time
db.createCollection("certification_history", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["repo_id", "date", "level", "evaluator"],
      properties: {
        repo_id: {
          bsonType: "objectId",
          description: "Reference to the repository"
        },
        date: {
          bsonType: "date",
          description: "Date of certification change"
        },
        level: {
          bsonType: "string",
          enum: ["None", "Bronze", "Silver", "Gold"],
          description: "Certification level"
        },
        evaluator: {
          bsonType: "string",
          description: "Name of evaluator"
        },
        notes: {
          bsonType: "string",
          description: "Notes about the certification change"
        }
      }
    }
  }
});