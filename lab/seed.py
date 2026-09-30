"""
World Monitor Lab - Database Seeder
Populates initial mock data for authentication, reports, telemetry, and system logs.
"""

import hashlib
from datetime import datetime
from lab.database import SessionLocal, init_db, User, Report, Telemetry, SystemLog

def hash_pw(password: str, salt: str = "wmsalt2026") -> str:
    return hashlib.sha256(f"{password}:{salt}".encode()).hexdigest()

def seed_lab():
    init_db()
    db = SessionLocal()
    try:
        # Check if already seeded
        if db.query(User).count() > 0:
            print("[Lab Seeder] Database already populated.")
            return

        print("[Lab Seeder] Seeding initial users, intelligence reports, and telemetry...")

        # 1. Users
        users = [
            User(
                username="admin",
                email="admin@worldmonitor.local",
                password_hash=hash_pw("Admin@WM2026!"),
                salt="wmsalt2026",
                role="admin",
                api_token="wm_sec_token_adm_9941",
                recovery_codes="RECOV-9912-4412-8871;RECOV-1192-3391-0021",
                internal_ip="10.240.12.5"
            ),
            User(
                username="analyst",
                email="analyst@worldmonitor.local",
                password_hash=hash_pw("Analyst@WM2026!"),
                salt="wmsalt2026",
                role="analyst",
                api_token="wm_sec_token_ana_4210",
                recovery_codes="RECOV-4421-9981-2231",
                internal_ip="10.240.12.18"
            ),
            User(
                username="viewer",
                email="viewer@worldmonitor.local",
                password_hash=hash_pw("Viewer@WM2026!"),
                salt="wmsalt2026",
                role="viewer",
                api_token="wm_sec_token_viw_1038",
                recovery_codes="RECOV-1102-8871-3321",
                internal_ip="10.240.12.89"
            ),
        ]
        db.add_all(users)
        db.commit()

        # 2. Intelligence Reports
        reports = [
            Report(
                id=1,
                title="Public Maritime Traffic Overview - Indian Ocean Sector",
                classification="PUBLIC",
                summary="Routine observation of commercial shipping lanes in the southern corridor.",
                content="Vessel transit counts are within nominal baselines. No unusual transponder anomalies observed.",
                notes="Verified by automated AIS ingest feed.",
                author_id=3  # viewer
            ),
            Report(
                id=2,
                title="Regional Weather Satellite Anomaly Diagnostic",
                classification="INTERNAL",
                summary="Thermal sensor calibration drift identified on MET-04 payload.",
                content="Telemetry analysis shows a 1.2 degree Kelvin offset on infrared channel 3 during periapsis pass.",
                notes="Calibration patch scheduled for maintenance window 4.",
                author_id=2  # analyst
            ),
            Report(
                id=3,
                title="CLASSIFIED: Strategic Satellite Orbit Shift Analysis",
                classification="RESTRICTED_TOP_SECRET",
                summary="Unscheduled orbital inclination change detected for foreign optical reconnaissance asset.",
                content="Sensor telemetry confirms delta-v burn at 03:14:22 UTC. Trajectory suggests repositioning over coastal radar installations. Restricted access only.",
                notes="Authorized for Directorate level analysts only.",
                author_id=1  # admin
            ),
            Report(
                id=4,
                title="Critical Border Surveillance Radar Feed Health",
                classification="RESTRICTED_TOP_SECRET",
                summary="Microwave uplink latency report across sector 7 perimeter stations.",
                content="Station K-09 reported intermittent packet loss on primary transponder. Backup encrypted fiber link activated.",
                notes="Security clearance Grade 1 required.",
                author_id=1  # admin
            )
        ]
        db.add_all(reports)

        # 3. Telemetry records
        telemetries = [
            Telemetry(station_code="STN-DELHI-01", satellite_id="SAT-INSAT-4B", signal_strength=94.2, coordinates="28.6139 N, 77.2090 E"),
            Telemetry(station_code="STN-MUMBAI-02", satellite_id="SAT-CARTOSAT-3", signal_strength=88.5, coordinates="19.0760 N, 72.8777 E"),
            Telemetry(station_code="STN-VIZAG-03", satellite_id="SAT-RISAT-2BR1", signal_strength=91.8, coordinates="17.6868 N, 83.2185 E"),
            Telemetry(station_code="STN-LADAKH-04", satellite_id="SAT-GSAT-7A", signal_strength=79.4, coordinates="34.1526 N, 77.5771 E"),
        ]
        db.add_all(telemetries)

        # 4. System Logs (with cleartext auth token seeded to demonstrate data storage/privacy vulnerability)
        logs = [
            SystemLog(
                level="INFO",
                message="System bootstrap completed. Sensor ingest pipeline active.",
                context="worker_thread=1; pool_size=16"
            ),
            SystemLog(
                level="DEBUG",
                message="User authentication successful for admin. Assigned session token wm_sec_token_adm_9941. Client IP 10.240.12.5",
                context="auth_module=legacy_session_mgr; auth_token=wm_sec_token_adm_9941; raw_pw_hash=e2a4...; cleartext_token=wm_sec_token_adm_9941"
            ),
            SystemLog(
                level="WARN",
                message="High memory utilization threshold reached on telemetry aggregation buffer.",
                context="mem_usage=84.2%"
            ),
        ]
        db.add_all(logs)
        db.commit()
        print("[Lab Seeder] Seed completed successfully.")
    finally:
        db.close()

if __name__ == "__main__":
    seed_lab()
