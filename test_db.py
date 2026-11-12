from database import get_connection

connection = get_connection()

if connection:
    print("Connection test completed!")
    connection.close()