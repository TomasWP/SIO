import random
from website import models

def check_database_table_exists(table_name):
    
        # Construct the SQL query
        query = "SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_name=%s)"
    
        # Execute the query and get the result
        result = models.db_query(query, (table_name,))
        if not result[0][0]:
            if table_name == "users":
                # Construct the SQL query
                query = "CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(255), password VARCHAR(255), admin BOOLEAN)"
            elif table_name == "products":
                query = "CREATE TABLE products (id SERIAL PRIMARY KEY, name VARCHAR(255), description VARCHAR(255), price VARCHAR(255), category VARCHAR(255), stock INTEGER)"
            else:
                query = "CREATE TABLE reviews (review_id SERIAL PRIMARY KEY, product_id INTEGER, user_id INTEGER, rating INTEGER, review VARCHAR(255))"

            # Execute the query
            models.db_query(query)

def create_user(username, password):
    # Generate a unique user id
    id = str(generate_random_id())
    
    # Add the user to the USER table
    models.db_query("INSERT INTO users (id, username, password, admin) VALUES (%s, %s, %s, %s, %s);",
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
    result = models.db_query("SELECT EXISTS(SELECT 1 FROM users WHERE id = %s);", (id,))
    return result[0][0]