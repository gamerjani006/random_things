#following tutorial from https://www.youtube.com/watch?v=pd-0G0MigUA

import sqlite3 as sql

conn = sql.connect(':memory:')

c=conn.cursor()

c.execute("""CREATE TABLE employees (
            first text,
            last text,
            pay integer
            )""")
 
conn.commit()

conn.close()
