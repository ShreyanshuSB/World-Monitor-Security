# Security Assessment — Architecture Map

## World Monitor Application: System Architecture

### Application Overview

World Monitor is a real-time global intelligence monitoring platform providing:
- Geospatial event visualization (2D/3D globe)
- Live data feed aggregation (RSS, webcams, satellite data)
- AI-powered event summarization
- Multi-tier user roles (Admin / Analyst / Viewer)
- REST API backend + React frontend dashboard

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     EXTERNAL CLIENTS                            │
│  Browser (Unauthenticated)  │  Authenticated User Sessions      │
└──────────────────────┬──────────────────────────────────────────┘
                       │ HTTPS
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                   FRONTEND LAYER                                │
│  React + Vite (SPA)                                             │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────────────┐  │
│  │  Globe View  │  │  Dashboard  │  │  Alert Management    │  │
│  │  (Cesium)    │  │  (Charts)   │  │  (Role-Gated UI)     │  │
│  └──────────────┘  └─────────────┘  └──────────────────────┘  │
│  Client-Side Auth State (Clerk)                                 │
│  LocalStorage / SessionStorage  │  IndexedDB                   │
└──────────────────────┬──────────────────────────────────────────┘
                       │ REST / WebSocket
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                   API LAYER (FastAPI)                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Authentication Middleware (Bearer Token / Clerk)        │  │
│  │  ┌─────────────────┐  ┌──────────────────────────────┐  │  │
│  │  │  /api/auth/*    │  │  /api/users/*               │  │  │
│  │  │  /api/reports/* │  │  /api/admin/*               │  │  │
│  │  │  /api/telemetry │  │  /api/config/*              │  │  │
│  │  └─────────────────┘  └──────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│  CORS Middleware  │  Rate Limiting (missing!)  │  HSTS (missing)│
└──────────────────────┬──────────────────────────────────────────┘
                       │ SQLAlchemy ORM
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                   DATA LAYER                                    │
│  SQLite Database (lab.db)                                       │
│  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────────┐  │
│  │  Users  │ │ Reports  │ │ Telemetry │ │   SystemLogs     │  │
│  └─────────┘ └──────────┘ └───────────┘ └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                   EXTERNAL INTEGRATIONS                         │
│  Satellite Uplink Gateway (Internal)  │  AI Summarization API   │
│  RSS/News Feed Aggregators            │  Webcam Streams         │
└─────────────────────────────────────────────────────────────────┘
```

### API Surface Map

| Endpoint | Method | Auth Required | Role | Notes |
|----------|--------|---------------|------|-------|
| `/api/auth/login` | POST | No | - | Credential authentication |
| `/api/users/profile` | GET | Yes | Any | Returns full DB model (vulnerable) |
| `/api/reports` | GET | Optional | - | Search vulnerable to SQLi |
| `/api/reports/{id}` | GET | Yes | Any | Missing ownership/clearance check |
| `/api/reports/{id}/notes` | POST | Yes | Analyst+ | Stored XSS sink |
| `/api/admin/telemetry-export` | GET | Yes | Admin (missing check) | BFLA |
| `/api/config/client` | GET | No | - | Leaks API keys |
| `/api/admin/system-logs` | GET | Yes | Admin | Cleartext tokens in logs |
| `/api/telemetry/live` | GET | No | - | Public telemetry |
| `/api/health` | GET | No | - | Health check |
| `/api/lab/patch/{key}` | POST | No | - | Lab control (not in prod) |

### Authentication Architecture

```
Token-Based Authentication
└── Bearer Token in Authorization header
    ├── Static tokens stored in DB (not JWT)
    ├── Backdoor: tokens prefixed "wm_forged_admin_" accepted (CRITICAL)
    └── Clerk OAuth (production only, not in lab)
```

### Data Classification Levels

| Level | Description |
|-------|-------------|
| PUBLIC | Open to all users |
| INTERNAL | Analyst and Admin only |
| RESTRICTED_TOP_SECRET | Admin only (but NOT enforced!) |

### Identified Security Boundaries

1. **Authentication Boundary** — Between anonymous and authenticated users
2. **Role Boundary** — Between Viewer / Analyst / Admin roles  
3. **Data Classification Boundary** — Between clearance levels
4. **Network Boundary** — Between public internet and internal gateway
5. **Admin Function Boundary** — Between regular and administrative operations
