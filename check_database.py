
import sqlite3

connection = sqlite3.connect("digital_notice_board.db")

cursor = connection.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")

tables = cursor.fetchall()

print("Tables in the database:")

for table in tables:
    print(table[0])

connection.close()

