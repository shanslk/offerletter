import sqlite3

# Connect to (or create) the database
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Create the users table
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'candidate')),
        offer_filename TEXT  -- optional: link to their offer letter blob
    )
''')

# Insert sample users
users = [
    ('admin1', 'adminpass', 'admin', None),
    ('candidate1', 'candipass', 'candidate', 'offer_candidate1.pdf')
]

c.executemany('INSERT OR IGNORE INTO users (username, password, role, offer_filename) VALUES (?, ?, ?, ?)', users)

conn.commit()
conn.close()

print("Database initialized and users added.")
