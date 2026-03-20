LOGS = {
    "brute_force": """
Failed login attempts: 312
Source IP: 45.83.122.14
Target: corp\\admin.jsmith
Protocol: SSH (port 22)
Timeframe: 4 minutes
Result: Account locked after threshold
""",

    "port_scan": """
Source IP: 10.0.0.45 (internal)
Destination: 192.168.1.0/24 (entire subnet)
Ports scanned: 1-65535
Protocol: TCP SYN
Duration: 2 minutes
Unique hosts reached: 254
""",

    "data_exfiltration": """
User: jdoe@company.com
Event: Large file transfer to external storage
Destination: dropbox.com
Data transferred: 4.7 GB in 12 minutes
Time: 11:45 PM (outside business hours)
Files: Q4_financials.xlsx, client_database.csv
""",
}