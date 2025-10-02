# Cybersecurity RAG Pipeline

A comprehensive Retrieval-Augmented Generation (RAG) pipeline for cybersecurity analysis, threat detection, and security knowledge management.

## 🚀 Features

- **Vector Database**: ChromaDB-based persistent storage with semantic search
- **Multi-Source Data Processing**: MITRE ATT&CK dataset, payload datasets, and cyberagent knowledge
- **Advanced Retrieval**: Context-aware similarity search with relevance scoring
- **Security Analysis**: Automated threat analysis, payload classification, and risk assessment
- **RAG-Enhanced Agents**: Intelligent security recommendations and pattern investigation
- **Batch Processing**: High-performance batch analysis capabilities
- **Comprehensive Logging**: Full pipeline monitoring and health checks

## 📋 Requirements

```bash
pip install -r requirements.txt
```

### Key Dependencies
- ChromaDB 0.4.18 - Vector database
- sentence-transformers 2.2.2 - Text embeddings
- pandas 2.1.4 - Data processing
- numpy 1.24.4 - Numerical computations
- scikit-learn 1.3.2 - ML utilities

## 🏗️ Architecture

```
RAG Pipeline Architecture
│
├── 📊 Data Processing Layer
│   ├── MITRE ATT&CK Dataset Processor
│   ├── Payload Dataset Processor
│   └── CyberAgents Knowledge Extractor
│
├── 🗄️ Storage Layer
│   ├── ChromaDB Vector Database
│   └── Metadata Management
│
├── 🔍 Retrieval Layer
│   ├── Semantic Similarity Search
│   ├── Query Classification
│   ├── Relevance Scoring
│   └── Context Aggregation
│
├── 🤖 RAG Agent Layer
│   ├── Threat Analysis Agent
│   ├── Payload Analysis Agent
│   ├── Security Recommendation Engine
│   └── Attack Pattern Investigator
│
└── 🎯 Orchestration Layer
    ├── Pipeline Management
    ├── Batch Processing
    ├── Health Monitoring
    └── Results Export
```

## 🔧 Quick Start

### 1. Initialize the Pipeline

```python
from rag_pipeline import create_rag_pipeline, RAGPipelineConfig

# Configure the pipeline
config = RAGPipelineConfig()
config.similarity_threshold = 0.6
config.top_k_results = 10

# Create the pipeline
pipeline = create_rag_pipeline(
    mitre_csv_path="mitre_attack_structured_dataset.csv",
    payload_csv_path="payload_dataset.csv", 
    cyberagents_path="cyberagents/",
    config=config
)
```

### 2. Query Knowledge Base

```python
# Simple knowledge base query
result = pipeline.query_knowledge_base("SQL injection prevention")

if result['status'] == 'success':
    print(f"Found {len(result['results'])} relevant documents")
    print(f"Confidence: {result['confidence_score']:.3f}")
    print(f"Context: {result['aggregated_context'][:200]}...")
```

### 3. Analyze Security Incidents

```python
# Define incident data
incident_data = {
    "indicators": ["SQL injection", "union select", "database attack"],
    "context": "Web application security breach",
    "payloads": [
        "' UNION SELECT username, password FROM users--",
        "admin' OR '1'='1'--"
    ]
}

# Analyze the incident
analysis = pipeline.analyze_security_incident(incident_data)

if analysis['status'] == 'success':
    threat = analysis['results']['threat_analysis']
    print(f"Threat Level: {threat['threat_level']}")
    print(f"Attack Vectors: {threat['attack_vectors']}")
    print(f"MITRE Techniques: {threat['mitre_techniques']}")
```

### 4. Batch Payload Analysis

```python
# Analyze multiple payloads
payloads = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "; cat /etc/passwd",
    "../../../etc/passwd"
]

batch_result = pipeline.analyze_payload_batch(payloads)

if batch_result['status'] == 'success':
    summary = batch_result['summary_stats']
    print(f"Analyzed {summary['total_payloads']} payloads")
    print(f"Payload types: {summary['payload_type_distribution']}")
```

## 📖 Detailed Usage

### Data Processing

The pipeline automatically processes three types of data:

1. **MITRE ATT&CK Dataset**: Structured cybersecurity attack techniques
2. **Payload Dataset**: Security payloads and attack signatures  
3. **CyberAgents Knowledge**: Agent-based security knowledge

```python
from rag_pipeline import ComprehensiveDataProcessor

processor = ComprehensiveDataProcessor()
processed_data = processor.process_all_datasets(
    mitre_csv_path, payload_csv_path, cyberagents_path
)
```

### Vector Database Management

```python
from rag_pipeline import CybersecurityVectorDB

# Initialize vector database
vector_db = CybersecurityVectorDB("my_security_db")

# Get database information
info = vector_db.get_collection_info()
print(f"Documents: {info['document_count']}")

# Search by MITRE technique
results = vector_db.search_by_mitre_id("T1110", top_k=5)
```

### Advanced Retrieval

```python
from rag_pipeline import AdvancedRAGRetriever, RAGQueryOptimizer

# Create retriever with optimization
retriever = AdvancedRAGRetriever(vector_db)
optimizer = RAGQueryOptimizer(retriever)

# Optimized retrieval with query expansion
context = optimizer.optimize_retrieval("brute force attack", top_k=8)

print(f"Query type: {context.query_type}")
print(f"Confidence: {context.confidence_score}")
print(f"Sources: {context.sources}")
```

### Security Agent Operations

```python
from rag_pipeline import RAGSecurityAgent

agent = RAGSecurityAgent(vector_db)

# Analyze threats
threat_indicators = ["suspicious login attempts", "multiple failed auth"]
threat_analysis = agent.analyze_threat(threat_indicators, "Authentication attack")

# Analyze payloads  
payload = "'; DROP TABLE users; --"
payload_analysis = agent.analyze_payload(payload)

# Get security recommendations
recommendations = agent.get_security_recommendations("SQL injection prevention")
```

## 🔧 Configuration Options

```python
config = RAGPipelineConfig()

# Vector database settings
config.vector_db_path = "cybersecurity_vectordb"
config.similarity_threshold = 0.6
config.top_k_results = 10

# Processing settings
config.max_context_length = 2000
config.batch_size = 50

# Feature flags
config.enable_caching = True
config.auto_update_db = True
```

## 📊 Pipeline Monitoring

```python
# Get pipeline statistics
stats = pipeline.get_pipeline_statistics()

print(f"Documents processed: {stats['pipeline_stats']['total_documents_processed']}")
print(f"Queries processed: {stats['pipeline_stats']['total_queries_processed']}")
print(f"Average query time: {stats['pipeline_stats']['average_query_time']:.3f}s")
print(f"System health: {stats['system_health']['vector_db_size']} documents")

# Health verification
verification = pipeline._verify_pipeline_health()
print(f"Overall health: {verification['overall_health']}")
```

## 🔄 Data Updates

```python
# Incremental update
update_result = pipeline.update_knowledge_base(
    mitre_csv_path="updated_mitre.csv",
    payload_csv_path="updated_payloads.csv", 
    cyberagents_path="updated_agents/",
    incremental=True
)

# Full rebuild
pipeline.initialize_pipeline(
    mitre_csv_path, payload_csv_path, cyberagents_path,
    force_rebuild=True
)
```

## 📁 Project Structure

```
assr/
├── rag_pipeline/
│   ├── __init__.py              # Package initialization
│   ├── vector_db.py             # ChromaDB vector database
│   ├── data_processor.py        # Data preprocessing pipeline
│   ├── ingestion.py             # Data ingestion system
│   ├── retrieval.py             # RAG retrieval system
│   ├── rag_agent.py             # Security analysis agents
│   └── main_pipeline.py         # Main orchestrator
├── cyberagents/                 # CyberAgents framework
│   ├── agents/                  # Security agent implementations
│   └── utils/                   # Utilities
├── mitre_attack_structured_dataset.csv
├── payload_dataset.csv
├── rag_example.py               # Complete usage example
├── requirements.txt             # Dependencies
└── README.md                    # This file
```

## 🚀 Running the Example

```bash
# Install dependencies
pip install -r requirements.txt

# Run the comprehensive example
python rag_example.py
```

The example demonstrates:
- Pipeline initialization and setup
- Knowledge base querying
- Security incident analysis  
- Batch payload processing
- System health monitoring

## 🔍 Key Classes and Methods

### RAGPipelineOrchestrator
Main orchestrator class for the entire pipeline.

```python
# Initialize pipeline
result = pipeline.initialize_pipeline(mitre_path, payload_path, agents_path)

# Analyze incidents
analysis = pipeline.analyze_security_incident(incident_data)

# Query knowledge base
results = pipeline.query_knowledge_base("security query")

# Batch processing
batch_results = pipeline.analyze_payload_batch(payloads)
```

### RAGSecurityAgent  
Specialized agent for security analysis.

```python
# Threat analysis
threat_result = agent.analyze_threat(indicators, context)

# Payload analysis
payload_result = agent.analyze_payload(payload, context)

# Security recommendations
recommendations = agent.get_security_recommendations(context)

# Attack pattern investigation
investigation = agent.investigate_attack_pattern(indicators)
```

## 🐛 Troubleshooting

### Common Issues

1. **Vector Database Access Error**
   - Ensure ChromaDB is properly installed
   - Check file permissions for database directory

2. **Memory Issues with Large Datasets**
   - Reduce batch_size in configuration
   - Process datasets in smaller chunks

3. **Poor Retrieval Results**
   - Lower similarity_threshold
   - Increase top_k_results
   - Check data preprocessing quality

### Logging

The pipeline provides comprehensive logging:

```python
import logging
logging.basicConfig(level=logging.INFO)
```

Logs include:
- Data processing progress
- Vector database operations  
- Query execution times
- Error details and stack traces

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- MITRE Corporation for the ATT&CK framework
- ChromaDB team for the vector database
- Sentence Transformers community
- All contributors to the cybersecurity datasets

---

**Ready to enhance your cybersecurity analysis with RAG technology!** 🛡️🚀
