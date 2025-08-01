import sqlite3

conn = sqlite3.connect("firewall.db")
cursor = conn.cursor()

# cursor.execute("""
# ALTER TABLE firewall_rules ADD COLUMN mac_address TEXT;
#                """)

# Add a few example rules
# cursor.executemany(
#     """
# INSERT INTO firewall_rules (port, protocol, action) VALUES (?, ?, ?)
# """,
#     [
#         (22, "tcp", "ACCEPT"),  # Allow SSH
#         (80, "tcp", "ACCEPT"),  # Allow HTTP
#         (21, "tcp", "DROP"),  # Block FTP
#     ],
# )

cursor.execute("""
# CREATE TABLE IF NOT EXISTS BlockedIP (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     ip_address TEXT NOT NULL,  
#     reason TEXT NOT NULL,
#     blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
# );
# """)

conn.commit()
conn.close()
print("Database and sample rules created.")
