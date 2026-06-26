# AI SOC Assistant

AI SOC Assistant is an AI-powered Security Operations Center (SOC) analyst platform built to automate log analysis, detect threats, map attacks to MITRE ATT&CK, prioritize alerts, and generate incident reports.

## Overview

Security analysts deal with huge volumes of logs every day. Manual investigation is slow and error-prone. AI SOC Assistant helps analysts by using AI to analyze logs, identify suspicious activities, explain attacks, and generate actionable reports.

## Features

* Upload and analyze security logs (CSV, JSON, TXT)
* Detect suspicious events and anomalies
* AI-powered threat explanation
* MITRE ATT&CK mapping
* Alert prioritization based on severity
* Incident report generation
* Interactive dashboard for monitoring
* Authentication system
* Threat analytics with charts

## Tech Stack

### Frontend

* React.js
* TailwindCSS
* Chart.js

### Backend

* FastAPI
* Python

### Database

* PostgreSQL

### AI Integration

* OpenAI API

## Project Structure

AI-SOC-Assistant/
│── backend/
│   ├── main.py
│   ├── routes/
│   ├── services/
│   ├── models/
│   └── utils/
│
│── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── assets/
│   │   ├── utils/
│   │   └── App.jsx
│
│── database/
│   ├── schema.sql
│
│── uploads/
│── sample_logs.csv
│── sample_logs.json
│── sample_logs.txt
│── README.md

## Installation

### Clone Repository

git clone https://github.com/Harimaniesh/AI-SOC-Assistant.git

cd AI-SOC-Assistant

## Backend Setup

cd backend

pip install -r requirements.txt

uvicorn main:app --reload

Backend runs on:
http://localhost:8000

## Frontend Setup

cd frontend

npm install

npm run dev

Frontend runs on:
http://localhost:5173

## Database Setup

Install PostgreSQL and create a database:

CREATE DATABASE ai_soc_assistant;

Import schema:

psql -U postgres -d ai_soc_assistant -f database/schema.sql

## Environment Variables

Create a .env file in backend:

OPENAI_API_KEY=your_openai_api_key
DATABASE_URL=postgresql://username:password@localhost/ai_soc_assistant

## API Endpoints

POST /upload-log → Upload logs

POST /analyze → Analyze logs

GET /alerts → Get detected alerts

GET /reports → Get incident reports

GET /dashboard → Dashboard analytics

## MITRE ATT&CK Integration

The system maps detected threats into MITRE ATT&CK techniques to improve incident understanding.

Example:

* T1059 → Command and Scripting Interpreter
* T1071 → Application Layer Protocol
* T1110 → Brute Force

## Future Improvements

* Real-time SIEM integration
* Live threat intelligence feeds
* SOC chatbot assistant
* User behavior analytics
* Automated incident response

## Screenshots

(Add screenshots here)

## Contributing

Contributions are welcome. Fork the repository and submit a pull request.

## License

This project is licensed under the MIT License.

## Author

Hari Maniesh
