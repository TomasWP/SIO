import json
import os
import psycopg2


def db_query(query, params=None):

    # Get the credentials for accessing the database
    credentials = read_json("/credentials/DataBaseCredentials.json")

    # Connect to the database
    conn = psycopg2.connect(
        host=credentials["host"],
        dbname=credentials["dbname"],
        user=credentials["user"],
        password=credentials["password"],
        port=credentials["port"]
    )
    # Initiate the cursor
    cur = conn.cursor()
    # Check if there is any parameters
    if params:
        # Execute query with parameters
        cur.execute(query, params)
    else:
        # Execute query without parameters
        cur.execute(query)
    # Define select_in_query as False by default
    select_in_query = False
    # Check if the query has SELECT
    if "SELECT" in query:
        # Fetch all the data
        data = cur.fetchall()
        select_in_query = True
    # Commit the connection
    conn.commit()
    # Close the cursor
    cur.close()
    # Close the connection
    conn.close()
    # Check if the query has SELECT
    if select_in_query:
        # Return the requested data
        return data
    
def read_json(filename):

    # Read the file and load its content as JSON
    with open(os.getcwd() + filename, "r", encoding="utf8") as file:
        data = json.load(file)
    file.close()

    return data