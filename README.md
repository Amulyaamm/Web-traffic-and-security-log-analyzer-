Web Traffic & Security Log Analyzer
* Overview
The Web Traffic & Security Log Analyzer is a tool designed to parse, analyze, and visualize Apache/Nginx log files. It helps identify suspicious activity, generate statistics, and produce reports with charts and alerts.

* Features
Parse Apache/Nginx access logs
Extract fields: IP, timestamp, method, path, status, size, user agent
Data cleaning & structuring with Pandas
Detect suspicious behavior (excessive 404s, repeated login attempts)
Web UI (Flask + Bootstrap) for log uploads & reports
SQLite storage for parsed logs
Dynamic tables with filtering & search
Visual dashboard with Chart.js / Matplotlib
Export suspicious IPs to CSV
Generate PDF weekly reports
Email alerts when thresholds are breached.

* Tech Stack
Backend: Python (Flask, Regex, Pandas, SQLite)
Frontend: HTML, CSS, Bootstrap, Chart.js
Visualization: Matplotlib / Plotly
Reporting: xhtml2pdf / WeasyPrint
Database: SQLite3

*Example Outputs
Top 10 IPs
Error rate trends
Suspicious IPs flagged
PDF report with charts
