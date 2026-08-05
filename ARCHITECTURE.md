# AI-IDS: Artificial Intelligence Intrusion Detection System

**Version:** 3.0  
**Architecture Pattern:** Clean Architecture + SOLID Principles + Repository Pattern + IoC Container  
**Presentation:** Streamlit multi-page application  
**Persistence:** SQLite (relational)  
**ML Runtime:** scikit-learn 1.9 + XGBoost (multi-class, 70 features, 15 classes)  
**Test Coverage:** 263 automated tests  

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Use Case Diagram](#2-use-case-diagram)
3. [Data Flow Diagram](#3-data-flow-diagram)
4. [Entity-Relationship Diagram](#4-entity-relationship-diagram)
5. [Sequence Diagrams](#5-sequence-diagrams)
6. [Database Schema](#6-database-schema)
7. [Dependency Injection Container](#7-dependency-injection-container)
8. [Machine Learning Layer](#8-machine-learning-layer)
9. [Network Capture Layer](#9-network-capture-layer)
10. [File Structure](#10-file-structure)

---

## 1. System Architecture

```mermaid
block-beta
    columns 1

    block:Presentation["Presentation Layer — Streamlit UI (12 pages)"]
        columns 6
        Dashboard["Dashboard"]
        Detection["Detection\n(CSV / PCAP)"]
        LiveCapture["Live Capture"]
        LiveFlows["Live Flows"]
        Alerts["Alerts"]
        Models["Models"]
        Logs["Logs"]
        Monitoring["Monitoring"]
        Blacklist["Blacklist"]
        Whitelist["Whitelist"]
        Settings["Settings"]
        Login["Login"]
    end

    space

    block:Services["Service Layer — Business Logic"]
        columns 4
        DS["DetectionService"]
        CAS["CsvAnalysisService"]
        PAS["PcapAnalysisService"]
        MS["ModelService"]
        AE["AlertEngine"]
        AS["AuthService"]
        ILS["IpListService"]
        MES["ModelEvaluationService"]
        MonS["MonitoringService"]
    end

    space

    block:ML["Machine Learning Layer"]
        columns 3
        ML["ModelLoader"]
        SMA["SklearnAdapter"]
        XBA["XGBoostAdapter"]
        FM["FeatureMapper"]
        FS["FeatureSchema"]
        LE["LabelEncoder"]
    end

    space

    block:Capture["Network Capture Layer"]
        columns 3
        NCS["NativeCaptureService\n(PacketSniffer + FlowAssembler\n+ FlowFeatureCalculator)"]
        CIC["CICFlowMeterCaptureService\n(FlowSession + scapy\n+ QueueWriter + GC)"]
        IFE["IFlowExtractor\n(NativeFlowExtractor\n+ CICFlowMeterAdapter)"]
    end

    space

    block:Repositories["Data Access Layer — Repositories"]
        columns 4
        UR["UserRepo"]
        DR["DetectionRepo"]
        ARepo["AlertRepo"]
        MRepo["ModelRepo"]
        LRepo["LogRepo"]
        WLRepo["WhitelistRepo"]
        BLRepo["BlacklistRepo"]
        SMRepo["SystemMetricRepo"]
    end

    space

    block:Infrastructure["Infrastructure Layer"]
        columns 3
        DB["SQLite\n(ai_ids.db)"]
        TG["TelegramNotifier"]
        BC["BcryptHasher"]
        LF["LoggerFactory"]
    end

    Presentation --> Services
    Services --> ML
    Services --> Capture
    Services --> Repositories
    Repositories --> Infrastructure
```

### Layer Responsibilities

| Layer | Responsibility | Key Components |
|-------|---------------|----------------|
| **Presentation** | Interactive web UI via Streamlit | 12 multi-page views, auth guard |
| **Services** | Business logic, orchestration, validation | DetectionService, AlertEngine, ModelService, AuthService |
| **ML** | Model loading, inference, feature alignment | ModelLoader, IModelAdapter, FeatureMapper, FeatureSchema |
| **Capture** | Packet sniffing, flow assembly, feature extraction | PacketSniffer, FlowAssembler, FlowFeatureCalculator, CICFlowMeter |
| **Repositories** | Data access abstraction over SQLite | 8 typed repository classes |
| **Infrastructure** | Cross-cutting concerns | SQLite persistence, Telegram notifications, password hashing, structured logging |

---

## 2. Use Case Diagram

```mermaid
usecaseDiagram
    actor "System Admin" as Admin
    actor "Input Channel\n(CSV / PCAP / Network)" as InputChannel
    actor "ML Engine" as MLEngine
    actor "Telegram Bot" as TelegramBot

    package "AI-IDS System" {
        usecase "UC-01: User Authentication" as UC01
        usecase "UC-02: Model Management\n(Register / Activate / Deactivate / Evaluate)" as UC02
        usecase "UC-03a: Analyze CSV File" as UC03a
        usecase "UC-03b: Analyze PCAP File" as UC03b
        usecase "UC-03c: Live Network Capture" as UC03c
        usecase "UC-03d: View Live Flows" as UC03d
        usecase "UC-04: IP List Management\n(Blacklist / Whitelist)" as UC04
        usecase "UC-05: Threat Detection\n(Feature Mapping + Classification\n+ Severity + Attack Type)" as UC05
        usecase "UC-06: Persist Detection Record" as UC06
        usecase "UC-07: Alert Aggregation\n& Escalation" as UC07
        usecase "UC-08: View Dashboard" as UC08
        usecase "UC-09: View Logs & Reports" as UC09
        usecase "UC-10: System Monitoring\n(CPU / RAM / Disk / Network)" as UC10
        usecase "UC-11: User & Settings\nManagement" as UC11
    }

    Admin --> UC01
    Admin --> UC02
    Admin --> UC04
    Admin --> UC08
    Admin --> UC09
    Admin --> UC10
    Admin --> UC11

    UC01 ..> UC02 : <<extend>>
    UC01 ..> UC04 : <<extend>>
    UC01 ..> UC08 : <<extend>>

    InputChannel --> UC03a
    InputChannel --> UC03b
    InputChannel --> UC03c

    UC03a --> UC05 : <<include>>
    UC03b --> UC05 : <<include>>
    UC03c --> UC05 : <<include>>

    UC05 --> UC06 : <<include>>
    UC05 --> UC07

    MLEngine --> UC05

    UC07 --> TelegramBot : <<include>>

    UC03c --> UC03d
```

### Use Case Relationship Matrix

| Relationship | Stereotype | Semantics |
|-------------|-----------|-----------|
| UC-01 → UC-02 | `<<extend>>` | Authentication is a precondition for model management |
| UC-01 → UC-04 | `<<extend>>` | Authentication is a precondition for IP list management |
| UC-01 → UC-08 | `<<extend>>` | Authentication is a precondition for dashboard access |
| UC-03a → UC-05 | `<<include>>` | CSV analysis always invokes threat detection |
| UC-03b → UC-05 | `<<include>>` | PCAP analysis always invokes threat detection |
| UC-03c → UC-05 | `<<include>>` | Live capture always invokes threat detection |
| UC-05 → UC-06 | `<<include>>` | Detection always persists a record to DB |
| UC-07 → TelegramBot | `<<include>>` | Alert escalation always dispatches Telegram notification |

### Use Case Specification Table

| ID | Use Case | Actor(s) | Preconditions | Postconditions | Trigger |
|----|----------|----------|---------------|----------------|---------|
| UC-01 | User Authentication | Admin | — | Active session established | Login form submission |
| UC-02 | Model Management | Admin | UC-01 complete | Model registered/activated/deactivated/evaluated | Model file upload or toggle |
| UC-03a | Analyze CSV File | Input Channel | Active model exists | Classification results per row | CSV file upload |
| UC-03b | Analyze PCAP File | Input Channel | Active model exists | Classification results per flow | PCAP file upload |
| UC-03c | Live Network Capture | Input Channel | Active model, interface selected | Real-time classified flows | Capture start |
| UC-03d | View Live Flows | Admin | UC-03c running | Live flow table with predictions | Page refresh |
| UC-04 | IP List Management | Admin | UC-01 complete | Blacklist/whitelist updated | Add/remove/import/export |
| UC-05 | Threat Detection | ML Engine | Feature vector available | class_index, confidence, severity, attack_type | Inference call |
| UC-06 | Persist Detection Record | System | UC-05 complete | Detection row in SQLite | UC-05 completion |
| UC-07 | Alert Aggregation & Escalation | System | UC-06 complete | Alert created/updated, Telegram sent if threshold met | UC-06 with malicious prediction |
| UC-08 | View Dashboard | Admin | UC-01 complete | Aggregated metrics, charts | Page navigation |
| UC-09 | View Logs & Reports | Admin | UC-01 complete | Filtered, searchable log data | Page navigation |
| UC-10 | System Monitoring | Admin | UC-01 complete | Live CPU/RAM/Disk/Network metrics | Page navigation |
| UC-11 | User & Settings Management | Admin | UC-01 complete | User/setting records updated | Form submission |

---

## 3. Data Flow Diagram

### 3.1 High-Level Data Flow

```mermaid
flowchart LR
    subgraph Input["Input Sources"]
        CSV["CSV File"]
        PCAP["PCAP File"]
        LIVE["Live Packets"]
    end

    subgraph Extraction["Feature Extraction"]
        CE["CSV Parser\n(raw_features dict)"]
        PE["IFlowExtractor\n(FlowFeatures)"]
        FE["FlowAssembler +\nFlowFeatureCalculator\n(70 features)"]
    end

    subgraph Alignment["Feature Alignment"]
        FM["FeatureMapper\n- normalize()\n- alias resolution\n- missing fill (0.0)\n- coverage check >= 50%"]
    end

    subgraph Inference["ML Inference"]
        AD["IModelAdapter\n- predict() -> class (0-14)\n- predict_proba() -> 15 probs\n- confidence = max(proba)"]
        LE["LabelEncoder\n.classes_[N] -> attack_type"]
        SV["classify_severity()\n- >= 0.90: CRITICAL\n- >= 0.70: HIGH\n- >= 0.40: MEDIUM\n- <  0.40: LOW"]
    end

    subgraph Output["Output"]
        DB["SQLite\n(detections table)"]
        ALT["AlertEngine\n(aggregate + escalate)"]
        TG["Telegram\nNotification"]
        CSV_OUT["CSV Files\n(captured_flows_master.csv\ncleaned_flows_master.csv)"]
        LOG["Log Repository"]
    end

    CSV --> CE --> FM
    PCAP --> PE --> FM
    LIVE --> FE --> FM

    FM --> AD
    AD --> LE
    AD --> SV

    AD --> DB
    ALT --> TG
    DB --> ALT
    AD --> CSV_OUT
    AD --> LOG
```

### 3.2 Feature Alignment Pipeline

```mermaid
flowchart TD
    A["raw_features: dict[str, float]"] --> B["FeatureMapper.map_with_report()"]
    B --> C{"Normalize all keys"}
    C --> D["lowercase, strip whitespace, remove dashes/underscores"]
    D --> E{"Alias resolution"}
    E --> F["Map CICIDS2017 naming variants"]
    F --> G{"Cascading lookup per required feature"}
    G --> H["1. Normalized key\n2. Raw cleaned key\n3. Base key (strip trailing digits)\n4. Bidirectional alias match"]
    H --> I{"Coverage check"}
    I -->|">= 50%"| J["feature_vector: np.ndarray (70,)"]
    I -->|"< 50%"| K["ValidationError raised"]
    H --> L["Missing features filled with 0.0"]
    L --> J
```

---

## 4. Entity-Relationship Diagram

```mermaid
erDiagram
    User {
        int id PK
        string username UK
        string password_hash
        string role
        bool is_active
        datetime created_at
        datetime last_login_at
    }

    ModelRecord {
        int id PK
        string name
        string file_path
        string model_type
        string version
        int features_count
        bool is_active
        datetime created_at
        string metadata
    }

    Detection {
        int id PK
        int model_id FK
        string source_ip
        string destination_ip
        int prediction
        float confidence
        string source_type
        string raw_features
        string severity
        string attack_type
        datetime created_at
    }

    Alert {
        int id PK
        string source_ip
        string threat_type
        int detection_id FK
        int occurrences
        datetime first_seen
        datetime last_seen
        bool is_acknowledged
        bool telegram_sent
    }

    LogEntry {
        int id PK
        string source
        string level
        string message
        string metadata
        datetime created_at
    }

    Whitelist_IP {
        int id PK
        string ip_address UK
        string reason
        datetime created_at
    }

    Blacklist_IP {
        int id PK
        string ip_address UK
        string reason
        datetime created_at
    }

    SystemMetric {
        int id PK
        float cpu_percent
        float ram_percent
        float disk_percent
        int network_sent_bytes
        int network_recv_bytes
        int active_threads
        datetime created_at
    }

    Settings {
        string key PK
        string value
        datetime updated_at
    }

    ModelRecord ||--o{ Detection : "classifies"
    Detection ||--o{ Alert : "triggers"
    User }o--|| Settings : "configures"
```

### Relationship Summary

| Relationship | Cardinality | Description |
|-------------|-------------|-------------|
| ModelRecord → Detection | 1 : N | Each detection is produced by exactly one model |
| Detection → Alert | 1 : N | A single detection may generate multiple alerts (aggregated) |

---

## 5. Sequence Diagrams

### 5.1 Threat Detection Pipeline (CSV / PCAP / Live)

```mermaid
sequenceDiagram
    autonumber
    participant U as User / Input Channel
    participant UI as Streamlit UI
    participant DS as DetectionService
    participant MS as ModelService
    participant FM as FeatureMapper
    participant AD as IModelAdapter
    participant LE as LabelEncoder
    participant DR as DetectionRepository
    participant AE as AlertEngine
    participant TN as TelegramNotifier

    U->>UI: Upload CSV/PCAP or start live capture
    UI->>DS: run(model_id, raw_features, source_type)
    
    DS->>MS: get_adapter(model_id)
    MS-->>DS: IModelAdapter
    
    Note over DS: required_features = adapter.required_features
    
    DS->>FM: validate_minimum_coverage(raw, required, 0.5)
    DS->>FM: map_with_report(raw_features, required_features)
    FM-->>DS: feature_vector (70,) + missing_features
    
    DS->>AD: predict(feature_vector)
    AD-->>DS: class_index (0-14)
    
    DS->>AD: predict_confidence(feature_vector)
    AD-->>DS: confidence (0.0 - 1.0)
    
    DS->>MS: get_label_encoder(model_id)
    MS-->>DS: LabelEncoder (15 classes)
    
    Note over DS: attack_type = encoder.classes_[class_index]<br/>severity = classify_severity(confidence, is_malicious)
    
    DS->>DR: add(Detection entity)
    DR-->>DS: persisted_detection
    
    DS->>AE: process_detection(persisted_detection)
    
    alt Malicious & threshold met
        AE->>TN: send_threat_alert(detection, model_name)
        TN-->>AE: HTTP 200 OK
    end
    
    AE-->>DS: Alert | None
    DS-->>UI: DetectionResult(detection, attack_type, confidence, severity)
    UI-->>U: Display results table
```

### 5.2 Live Capture Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant UI as Streamlit UI
    participant LCS as LiveCaptureService
    participant PS as PacketSniffer
    participant FA as FlowAssembler
    participant FFC as FlowFeatureCalculator
    participant DS as DetectionService
    participant CSV as CSV Writer

    UI->>LCS: start(interface, model_id, model_name)
    LCS->>PS: start(interface)
    
    loop Every captured packet
        PS->>FA: add_packet(src_ip, dst_ip, ports, protocol, ...)
        Note over FA: Groups packets into bidirectional flows<br/>by canonical 5-tuple key
    end
    
    loop Every 2 seconds (flush_loop)
        LCS->>FA: pop_idle_flows(now)
        FA-->>LCS: list[Flow]
        
        loop Per idle flow
            LCS->>FFC: compute(flow)
            FFC-->>LCS: FlowFeatures(features: dict[70])
            LCS->>DS: run(model_id, features, "live")
            DS-->>LCS: DetectionResult
            Note over LCS: Creates LiveFlowRecord with<br/>prediction, confidence, severity, attack_type
        end
        
        LCS->>CSV: _write_flows_to_csv(records)
    end
    
    UI->>LCS: get_recent_flows(limit)
    LCS-->>UI: List[LiveFlowRecord]
```

### 5.3 Authentication Sequence

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant UI as Login Page
    participant AS as AuthService
    participant UR as UserRepository
    participant PH as BcryptPasswordHasher

    U->>UI: Enter username + password
    UI->>AS: login(username, password)
    AS->>UR: get_by_username(username)
    UR-->>AS: User | None
    
    alt User not found
        AS-->>UI: raises AuthenticationError
    end
    
    AS->>PH: verify(password, user.password_hash)
    PH-->>AS: True | False
    
    alt Password incorrect
        AS-->>UI: raises AuthenticationError
    end
    
    AS->>UR: update_last_login(user.id)
    AS-->>UI: AuthResult(success=True)
    UI->>UI: Set session_state["authenticated"] = True
    UI->>UI: Navigate to Dashboard
```

### 5.4 Alert Escalation Sequence

```mermaid
sequenceDiagram
    autonumber
    participant DS as DetectionService
    participant AE as AlertEngine
    participant AR as AlertRepository
    participant ILS as IpListService
    participant TN as TelegramNotifier

    DS->>AE: process_detection(detection, model_name)
    
    AE->>ILS: is_blacklisted(source_ip)
    ILS-->>AE: True | False
    
    alt IP is blacklisted
        AE-->>DS: None (suppressed)
    end
    
    AE->>AR: find_active_window(source_ip, threat_type, window_seconds)
    AR-->>AE: existing_alert | None
    
    alt Alert exists within window
        AE->>AR: increment_occurrences(existing_alert.id)
        Note over AE: Update last_seen timestamp
    else New alert
        AE->>AR: add(new_alert)
    end
    
    Note over AE: Check escalation thresholds:<br/>- CRITICAL: >= 3 occurrences<br/>- HIGH: >= 5 occurrences<br/>- MEDIUM: >= 10 occurrences<br/>- LOW: >= 15 occurrences
    
    alt Escalation threshold met
        AE->>TN: send_escalation_alert(alert, model_name)
        TN-->>AE: HTTP 200 OK
        AE->>AR: mark_telegram_sent(alert.id)
    end
    
    AE-->>DS: Alert entity | None
```

---

## 6. Database Schema

```mermaid
flowchart LR
    subgraph Tables["SQLite Database — ai_ids.db"]
        direction TB
        U["users\n----------\nPK id\n   username (UK)\n   password_hash\n   role\n   is_active\n   created_at\n   last_login_at"]
        
        S["settings\n----------\nPK key\n   value\n   updated_at"]
        
        M["models\n----------\nPK id\n   name\n   file_path\n   model_type\n   version\n   features_count\n   is_active\n   created_at\n   metadata"]
        
        D["detections\n----------\nPK id\nFK model_id -> models\n   source_ip\n   destination_ip\n   prediction\n   confidence\n   source_type\n   raw_features (JSON)\n   severity\n   attack_type\n   created_at"]
        
        A["alerts\n----------\nPK id\nFK detection_id -> detections\n   source_ip\n   threat_type\n   occurrences\n   first_seen\n   last_seen\n   is_acknowledged\n   telegram_sent"]
        
        L["logs\n----------\nPK id\n   source\n   level\n   message\n   metadata (JSON)\n   created_at"]
        
        WL["whitelist_ips\n----------\nPK id\nUK ip_address\n   reason\n   created_at"]
        
        BL["blacklist_ips\n----------\nPK id\nUK ip_address\n   reason\n   created_at"]
        
        SM["system_metrics\n----------\nPK id\n   cpu_percent\n   ram_percent\n   disk_percent\n   network_sent_bytes\n   network_recv_bytes\n   active_threads\n   created_at"]
    end

    M -->|1:N| D
    D -->|1:N| A
```

### Performance Indexes

| Index Name | Table | Columns | Purpose |
|-----------|-------|---------|---------|
| `idx_detections_created_at` | detections | created_at | Time-range queries on detection history |
| `idx_alerts_source_ip` | alerts | source_ip | IP-based alert lookups |
| `idx_logs_created_at` | logs | created_at | Log chronology queries |
| `idx_logs_source` | logs | source | Filter by log source module |
| `idx_logs_level` | logs | level | Filter by severity level |
| `idx_logs_source_level` | logs | (source, level) | Composite filter for targeted diagnostics |
| `idx_whitelist_ip` | whitelist_ips | ip_address | Fast IP whitelist membership check |
| `idx_blacklist_ip` | blacklist_ips | ip_address | Fast IP blacklist membership check |

### Schema Migrations

Two automatic migrations run on startup for existing databases:
- `_migrate_add_severity()`: Adds `severity TEXT NOT NULL DEFAULT ''` to `detections`
- `_migrate_add_attack_type()`: Adds `attack_type TEXT NOT NULL DEFAULT ''` to `detections`

---

## 7. Dependency Injection Container

```mermaid
flowchart TD
    subgraph Container["Container (process-wide IoC singleton via @lru_cache)"]
        direction TB
        
        subgraph Repos["Data Access Repositories"]
            direction LR
            UR["UserRepository(db)"]
            DR["DetectionRepository(db)"]
            ARepo["AlertRepository(db)"]
            MRepo["ModelRepository(db)"]
            LRepo["LogRepository(db)"]
            WLRepo["WhitelistRepository(db)"]
            BLRepo["BlacklistRepository(db)"]
            SMRepo["SystemMetricRepository(db)"]
        end
        
        subgraph Infra["Infrastructure Components"]
            direction LR
            TG["TelegramNotifier()"]
            BC["BcryptPasswordHasher()"]
            LF["LoggerFactory"]
        end
        
        subgraph Core["Core Application Services"]
            direction LR
            AS["AuthService(user_repo, hasher, log_repo)"]
            MS["ModelService(model_repo, log_repo)"]
            ILS["IpListService(whitelist_repo, blacklist_repo, log_repo)"]
            AE["AlertEngine(alert_repo, ip_list_service, notifier)"]
            DS["DetectionService(model_svc, detection_repo, log_repo, alert_engine)"]
            CAS["CsvAnalysisService(detection_svc, model_svc)"]
            PAS["PcapAnalysisService(detection_svc, flow_extractor)"]
            MonS["MonitoringService(metric_repo, detection_repo, alert_repo)"]
            MES["ModelEvaluationService(model_svc)"]
        end
    end

    DB["DatabaseConnection"] --> Repos
    Repos --> Core
    Infra --> Core
```

### Dependency Resolution Order

| Priority | Component | Dependencies |
|----------|-----------|-------------|
| 1 | `DatabaseConnection` | SQLite file path |
| 2 | Repositories (8) | `DatabaseConnection` |
| 3 | `TelegramNotifier` | Environment variables (BOT_TOKEN, CHAT_ID) |
| 4 | `BcryptPasswordHasher` | — |
| 5 | `AuthService` | UserRepository, BcryptPasswordHasher, LogRepository |
| 6 | `ModelService` | ModelRepository, LogRepository |
| 7 | `IpListService` | WhitelistRepository, BlacklistRepository, LogRepository |
| 8 | `AlertEngine` | AlertRepository, IpListService, TelegramNotifier |
| 9 | `DetectionService` | ModelService, DetectionRepository, LogRepository, AlertEngine |
| 10 | `CsvAnalysisService` | DetectionService, ModelService |
| 11 | `PcapAnalysisService` | DetectionService, IFlowExtractor |
| 12 | `MonitoringService` | SystemMetricRepository, DetectionRepository, AlertRepository |

All services are lazily instantiated as process-wide singletons.

---

## 8. Machine Learning Layer

```mermaid
flowchart TD
    subgraph Interfaces["Abstract Interfaces (DIP)"]
        IMA["IModelAdapter\n─────────────\n+ predict(ndarray) -> int\n+ predict_confidence(ndarray) -> float\n+ required_features: list[str]"]
        IFE["IFlowExtractor\n─────────────\n+ extract_from_pcap(path) -> list[FlowFeatures]"]
    end

    subgraph Adapters["Concrete Adapters"]
        SMA["SklearnCompatibleModelAdapter\n─────────────\nWraps scikit-learn estimators\nUses predict() + predict_proba()\nReshapes to (1, -1) for 2D input"]
        XBA["XGBoostBoosterAdapter\n─────────────\nWraps native XGBoost Booster\nUses DMatrix with feature_names\nBinary classification via threshold"]
    end

    subgraph Loading["Model Loading Pipeline"]
        ML["ModelLoader.load(path, type_hint)"]
        JP["_load_joblib_or_pickle()\n-> joblib.load() or pickle.load()\n-> unwrap dict wrapper if needed"]
        XB["_load_xgboost_booster()\n-> xgb.Booster.load_model()\n-> XGBoostBoosterAdapter"]
    end

    subgraph Schema["Feature Schema Resolution"]
        FS["resolve_feature_schema(path, object, type)"]
        SC1["1. Sidecar JSON (highest priority)\n   .joblib.meta.json\n   Ensures consistent ordering"]
        SC2["2. Dict Wrapper (medium priority)\n   model['feature_names']"]
        SC3["3. Model Attributes (lowest priority)\n   estimator.feature_names_in_\n   booster.feature_names"]
    end

    subgraph Mapping["Feature Mapping Engine"]
        FMAP["FeatureMapper\n─────────────\n- normalize(): lowercase, strip, clean\n- aliases: 80+ CICIDS2017 name mappings\n- cascading lookup: 4-level fallback\n- missing_value_fill: 0.0\n- validate_minimum_coverage(): >= 50%"]
    end

    IMA --> SMA
    IMA --> XBA
    ML --> JP --> SMA
    ML --> XB --> XBA
    FS --> SC1
    FS --> SC2
    FS --> SC3
    SMA --> FMAP
    XBA --> FMAP
```

### Model Specifications

| Property | Random Forest V3 | XGBoost Pipeline V2 |
|----------|-----------------|---------------------|
| File | `random_forest_v3.joblib` (24 MB) | `xgboost_pipeline_v2.joblib` (1.1 MB) |
| Type | `RandomForestClassifier` | `XGBClassifier` |
| Estimators | 150 decision trees | Gradient boosted trees |
| Features | 70 (CICIDS2017) | 70 (CICIDS2017) |
| Classes | 15 (multi-class) | 15 (multi-class) |
| `predict_proba()` | Yes (15-class softmax) | Yes (15-class softmax) |
| Sidecar | `random_forest_v3.joblib.meta.json` | `xgboost_pipeline_v2.joblib.meta.json` |
| Feature ordering | Identical to XGBoost | Identical to RF |

### Label Encoder Classes (15)

| Index | Class Name | Index | Class Name |
|-------|-----------|-------|-----------|
| 0 | BENIGN | 8 | Heartbleed |
| 1 | Bot | 9 | Infiltration |
| 2 | DDoS | 10 | PortScan |
| 3 | DoS GoldenEye | 11 | SSH-Patator |
| 4 | DoS Hulk | 12 | Web Attack - Brute Force |
| 5 | DoS Slowhttptest | 13 | Web Attack - Sql Injection |
| 6 | DoS slowloris | 14 | Web Attack - XSS |
| 7 | FTP-Patator | | |

### Severity Classification

| Condition | Severity |
|-----------|----------|
| `prediction == 0` (BENIGN) | `""` (empty) |
| `confidence >= 0.90` | `CRITICAL` |
| `confidence >= 0.70` | `HIGH` |
| `confidence >= 0.40` | `MEDIUM` |
| `confidence < 0.40` | `LOW` |

---

## 9. Network Capture Layer

```mermaid
flowchart TD
    subgraph NativeMode["Native Capture Pipeline"]
        direction TB
        NS["PacketSniffer\n(scapy.sniff)\non_packet callback"]
        FA["FlowAssembler\n- add_packet()\n- canonical 5-tuple key\n- idle_timeout eviction\n- pop_idle_flows()"]
        FFC["FlowFeatureCalculator\n- compute(flow) -> FlowFeatures\n- 70 CICIDS2017 features\n- forward/backward split"]
        NDS["DetectionService.run()"]
        
        NS -->|"every packet"| FA
        FA -->|"every 2s flush"| FFC
        FFC --> NDS
    end

    subgraph CICMode["CICFlowMeter Capture Pipeline"]
        direction TB
        AS["scapy.AsyncSniffer\n_on_packet()"]
        CFS["cicflowmeter.FlowSession\n- process(pkt)\n- EXPIRED_UPDATE = 10s\n- garbage_collect(time.time())"]
        QW["_QueueWriter\n(completed_flows deque)"]
        FL["_flush_completed_flows()\n(every 10s)"]
        CAS["CsvAnalysisService.analyze()\n(reads cleaned CSV,\n runs full ML pipeline)"]
        WB["Write ML results back\nprediction, confidence,\nattack_type columns"]
        
        AS -->|"every packet"| CFS
        CFS -->|"GC expired flows"| QW
        QW --> FL
        FL --> CAS
        CAS --> WB
    end

    subgraph PCAP["PCAP File Analysis"]
        direction TB
        IFE2["IFlowExtractor.extract_from_pcap(path)"]
        NFE["NativeFlowExtractor\n-> FlowFeatureCalculator\n-> 70 features"]
        CICAD["CICFlowMeterAdapter\n-> cicflowmeter.FlowSession\n-> DataFrame\n-> FeatureMapper\n-> 70 features"]
        PAS2["PcapAnalysisService.analyze()"]
        
        IFE2 --> NFE
        IFE2 --> CICAD
        NFE --> PAS2
        CICAD --> PAS2
    end
```

### Bug Fixes Applied to CICFlowMeter Integration

| Bug | Symptom | Fix |
|-----|---------|-----|
| **BUG #1 (Fatal)** | `FlowSession.__init__` crashes: `RuntimeError("no output_mode provided")` | Monkey-patch `output_writer_factory` in module namespace to return `_QueueWriter` when `output_mode=None` |
| **BUG #2** | `toPacketList()` deletes `output_writer` when sniffer stops | Wrap with `_safe_toPacketList()` that does GC and returns empty `PacketList` without deleting writer |
| **BUG #3** | `EXPIRED_UPDATE = 240s` too slow for IDS latency | Patch `_fs_mod.EXPIRED_UPDATE = 10` (10-second flow expiry) |
| **BUG #4** | `process()` only calls GC every 1000 packets | Restore `garbage_collect(time.time())` call in flush thread |

---

## 10. File Structure

```
AI_IDS_3/
├── cli.py                          # Command-line interface (8 commands)
├── main.py                         # Application entry point
├── ARCHITECTURE.md                 # This document
├── DEPLOYMENT_FILES.txt            # Deployment manifest (73+ items)
├── requirements.txt                # Python dependencies
├── .env                            # Environment configuration
│
├── config/
│   ├── constants.py                # Enums, thresholds, defaults
│   └── settings.py                 # Pydantic settings, path resolution
│
├── core/
│   ├── entities/
│   │   ├── user.py                 # User domain entity
│   │   ├── detection.py            # Detection domain entity + classify_severity()
│   │   ├── alert.py                # Alert domain entity
│   │   ├── model_record.py         # ModelRecord domain entity
│   │   ├── log_entry.py            # LogEntry domain entity
│   │   ├── ip_list_entry.py        # IP list entry domain entity
│   │   └── system_metric.py        # SystemMetric domain entity
│   └── exceptions.py               # Custom exception hierarchy
│
├── database/
│   ├── connection.py               # SQLite connection management
│   └── schema.py                   # DDL, indexes, migrations
│
├── ml/
│   ├── interfaces.py               # IModelAdapter, IFlowExtractor (ABCs)
│   ├── model_loader.py             # Deserialization broker (joblib/pickle/xgboost)
│   ├── model_adapter.py            # SklearnCompatibleModelAdapter
│   ├── xgboost_booster_adapter.py  # XGBoostBoosterAdapter
│   ├── feature_mapper.py           # Semantic feature alignment engine
│   ├── feature_schema.py           # Dynamic schema resolution (sidecar-first)
│   └── cicflowmeter_adapter.py     # CICFlowMeter PCAP adapter
│
├── capture/
│   ├── packet_sniffer.py           # scapy-based packet sniffer
│   ├── flow.py                     # Flow data structure
│   ├── flow_assembler.py           # 5-tuple flow grouping + idle eviction
│   ├── flow_feature_calculator.py  # 70-feature CICIDS2017 calculator
│   ├── live_capture_service.py     # Native capture pipeline (singleton)
│   ├── cicflowmeter_live_capture_service.py  # CICFlowMeter capture pipeline
│   ├── native_pcap_extractor.py    # PCAP extractor (native)
│   ├── cicflowmeter_adapter.py     # PCAP extractor (CICFlowMeter)
│   └── extractor_factory.py        # Extractor factory (env-based selection)
│
├── repositories/
│   ├── user_repository.py
│   ├── detection_repository.py
│   ├── alert_repository.py
│   ├── model_repository.py
│   ├── log_repository.py
│   ├── whitelist_repository.py
│   ├── blacklist_repository.py
│   └── system_metric_repository.py
│
├── services/
│   ├── container.py                # IoC composition root
│   ├── detection_service.py        # Unified inference orchestrator
│   ├── csv_analysis_service.py     # Batch CSV analysis
│   ├── pcap_analysis_service.py    # PCAP file analysis
│   ├── model_service.py            # Model registry + adapter cache
│   ├── alert_engine.py             # Alert aggregation + escalation
│   ├── auth_service.py             # Authentication + password management
│   ├── ip_list_service.py          # Blacklist/whitelist operations
│   ├── monitoring_service.py       # System metrics collection
│   └── model_evaluation_service.py # Model performance evaluation
│
├── infrastructure/
│   ├── logging/
│   │   └── logger_factory.py       # Structured logging factory
│   ├── notifications/
│   │   └── telegram_notifier.py    # Async Telegram notifications
│   └── security/
│       └── password_hasher.py      # Bcrypt password hashing
│
├── ui/
│   ├── app.py                      # Streamlit app entry point
│   ├── auth_guard.py               # Session-based auth guard
│   └── pages/
│       ├── login.py                # Authentication page
│       ├── dashboard.py            # System overview dashboard
│       ├── detection.py            # CSV & PCAP analysis
│       ├── live_capture.py         # Live capture control
│       ├── live_flows.py           # Live flow viewer
│       ├── alerts.py               # Alert management
│       ├── logs.py                 # System logs viewer
│       ├── models.py               # Model registry management
│       ├── monitoring.py           # System resource monitoring
│       ├── blacklist.py            # IP blacklist management
│       ├── whitelist.py            # IP whitelist management
│       └── settings.py             # Application settings
│
├── models/                         # Trained ML model artifacts
│   ├── random_forest_v3.joblib     # Random Forest V3 (70 features, 15 classes)
│   ├── random_forest_v3.joblib.meta.json
│   ├── xgboost_pipeline_v2.joblib  # XGBoost V2 (70 features, 15 classes)
│   ├── xgboost_pipeline_v2.joblib.meta.json
│   ├── label_encoder.joblib        # LabelEncoder (15 attack classes)
│   └── scaler.joblib               # StandardScaler
│
└── tests/
    ├── test_database.py            # Database + repository tests (30)
    ├── test_repositories.py        # Repository + service tests (17)
    ├── test_security.py            # Auth, password, validation tests (40)
    ├── test_capture_layer.py       # Capture layer tests (31)
    ├── test_ml_layer.py            # ML layer tests (24)
    ├── test_telegram_notifier.py   # Telegram notifier tests (30)
    ├── test_services_layer.py      # Service integration tests (27)
    └── test_model_integration.py   # End-to-end model tests (29)
```
