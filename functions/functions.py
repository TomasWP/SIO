import random, json, os, psycopg2
from functions import functions


def check_database_table_exists(table_name):
    
        # Construct the SQL query
        query = "SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_name=%s)"
    
        # Execute the query and get the result
        result = functions.db_query(query, (table_name,))
        if not result[0][0]:
            if table_name == "users":
                # Construct the SQL query
                query = "CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(255), password VARCHAR(255), admin BOOLEAN)"
            elif table_name == "products":
                query = "CREATE TABLE products (id SERIAL PRIMARY KEY, name VARCHAR(255), description VARCHAR(255), price VARCHAR(255), category VARCHAR(255), stock INTEGER)"
            else:
                query = "CREATE TABLE reviews (review_id SERIAL PRIMARY KEY, product_id INTEGER, user_id INTEGER, rating INTEGER, review VARCHAR(255))"

            # Execute the query
            functions.db_query(query)

def create_user(username, password):
    # Generate a unique user id
    id = str(generate_random_id())
    
    # Add the user to the USER table
    functions.db_query("INSERT INTO users (id, username, password, admin) VALUES (%s, %s, %s, %s);",
            (id, username, password, False)
    )
    # Return the created user
    return id
    
def generate_random_id():
    # Generate a random ID
    random_id = random.randint(100000, 999999)

    # Check if the generated ID already exists, regenerate if necessary
    while check_id_existence(random_id):
        random_id = random.randint(100000, 999999)

    return random_id


def check_id_existence(id):
    result = functions.db_query("SELECT EXISTS(SELECT 1 FROM users WHERE id = %s);", (id,))
    return result[0][0]

def search_user_by_username(username):
    # Construct the SQL query
    query = "SELECT * FROM users WHERE username = %s"
    
    # Execute the query and get the result
    result = functions.db_query(query, (username,))

    # If no user is found, return None
    if not result:
        return None

    # Return the user data
    return result[0]

def validate_login(username, password):

    # If username is None, return False (user not found)
    if username is None:
        return False
    else:
        # Fetch the user's password
        query = "SELECT password FROM users WHERE username = %s"
        result = functions.db_query(query, (username,))
        # Check if there is a password
        if not result:
            return None
        # Check if the provided password matches the user's password
        if result[0][0] == password:
            return True
        else:
            return False
        
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