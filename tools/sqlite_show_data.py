import sqlite3 

# Connecting to sqlite 
# connection object 
connection_obj = sqlite3.connect('/Users/seal/Documents/GitHub/gogoth/shortener.db') 

# cursor object 
cursor_obj = connection_obj.cursor() 

# to select all column we will use 
statement = '''SELECT * FROM urls'''

cursor_obj.execute(statement) 

print("All the data") 
output = cursor_obj.fetchall() 
for row in output: 
    print(row) 

connection_obj.commit() 

# Close the connection 
connection_obj.close()
