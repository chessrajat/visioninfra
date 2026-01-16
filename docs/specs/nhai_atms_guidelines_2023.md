# Advanced Traffic Management System (ATMS)
## Functional & Technical Specifications
### National Highways Authority of India (NHAI)
**October 2023**

---

## 1. Introduction

This document defines the **functional and technical specifications** for implementing
Advanced Traffic Management Systems (ATMS) on **National Highways and Expressways**.

ATMS aims to:
- Improve road safety
- Enhance traffic efficiency
- Enable real-time monitoring and response
- Support enforcement agencies

This document supersedes earlier ATMS circulars issued prior to 15.09.2016. :contentReference[oaicite:0]{index=0}

---

## 2. Scope of ATMS

ATMS includes the following **core sub-systems**:

1. Video Surveillance System / Traffic Monitoring Camera System (TMCS)
2. Video Incident Detection & Enforcement System (VIDES)
3. Vehicle Actuated Speed Display System (VASD)
4. Variable Message Sign System (VMS)
5. Emergency Roadside Telephones (ERT)
6. Mobile Radio Communication System (MRCS)
7. ATMS Command & Control Center with ATMS Software
8. Power Supply & Field Equipment
9. Network Infrastructure & Data Communication

---

## 3. Key Objectives

ATMS shall support:

- Accident & incident detection
- Real-time traffic monitoring
- Enforcement through challans
- Congestion management
- Weather & visibility alerts
- Emergency response coordination
- Data-driven decision making

---

## 4. Video Surveillance / Traffic Monitoring (TMCS)

### Functions
- Continuous CCTV monitoring
- Live & recorded video access
- Event verification
- Support for analytics modules

### Requirements
- Day & night operation
- Centralized monitoring
- Integration with ATMS software
- Video retention as per policy

---

## 5. Video Incident Detection & Enforcement System (VIDES)

### Mandatory Events
- Accident detection
- Stopped vehicle (threshold based)
- Wrong-way driving
- Pedestrian on highway
- Animal crossing
- Debris on road

### Enforcement Capabilities
- ANPR-based violation detection
- Speed violation
- Red light violation
- Evidence capture (images + video)

---

## 6. Vehicle Actuated Speed Display System (VASD)

### Purpose
- Display real-time vehicle speed
- Encourage speed compliance
- Support enforcement

---

## 7. Variable Message Signs (VMS)

### Purpose
- Traffic alerts
- Diversions
- Weather warnings
- Emergency messages

### Control
- Centrally managed
- Configurable via ATMS software

---

## 8. Emergency Roadside Telephones (ERT)

### Features
- SOS calls to ATMS Control Center
- Location identification
- Integration with emergency services

---

## 9. Mobile Radio Communication System (MRCS)

### Purpose
- Communication between:
  - Patrol vehicles
  - ATMS control center
  - Emergency response teams

---

## 10. ATMS Command & Control Center

### Functions
- Central monitoring of all subsystems
- Incident management
- Video wall visualization
- Report generation
- Data analytics

### Levels
- Central (NHAI HQ)
- Regional
- Corridor / Project level

---

## 11. Functional Requirements (General)

ATMS systems shall:
- Operate 24x7x365
- Support redundancy & failover
- Log all events and actions
- Provide role-based access
- Support API integrations

---

## 12. Power & Infrastructure

- Dual power supply (Grid + Backup)
- UPS support
- Solar power where applicable
- Environmental protection for field equipment

---

## 13. Data, Logging & Reporting

- Central data storage
- Video & event logs
- Performance reports
- SLA monitoring
- Integration with enforcement databases

---

## 14. Disaster Management Integration

ATMS shall integrate with:
- NDMA
- State Disaster Authorities
- Emergency services
- Police & enforcement agencies

---

## 15. Standards & Compliance

All equipment and systems must comply with:
- BIS standards
- IEC / ISO standards
- Relevant Indian Road Congress (IRC) guidelines

---

## 16. Appendices (Referenced)

- Appendix A: Location guidelines for ATMS equipment
- Appendix B: Service Level Agreements & penalties
- Appendix C: ATMS Control Center staffing & organization
- Appendix D: Reporting & data lake integration

---

## 17. Implementation Philosophy

> ATMS is a **mission-critical infrastructure system**.
> Reliability, accuracy, and response time are mandatory.

