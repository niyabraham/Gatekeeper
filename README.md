Project Documentation : Macro enabled Excel Files’ Security and Scanning 

Objective
The Gatekeeper project is an automated security and scanning workflow designed to handle incoming macro enabled Excel files. Its primary goal is to intercept potential threats (such as malicious macros) before any team member opens the files, ensuring a secure environment across operations.

Workflow 
●	Ingestion & Automated Scanning: All incoming macro-enabled Excel files are automatically intercepted and scanned for security vulnerabilities, malicious code, and dangerous macros.
●	Quarantine Isolation: If a file is flagged as malicious or high-risk, the system instantly blocks it and moves it to a secure quarantine directory to prevent any system exposure.
●	Automated Cleanup & Processing: Safe files pass the security check and are automatically processed, cleaned, and stored in a designated directory ready for team utilization.
●	Audit Logging: Every single action—including file scans, block events, quarantine movements, and successful cleanups—is comprehensively tracked in an immutable audit log for compliance and review.




