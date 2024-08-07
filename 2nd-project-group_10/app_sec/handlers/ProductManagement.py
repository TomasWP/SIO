import random, os, json
from datetime import datetime
from handlers.Retrievers import get_product_by_id
from handlers.DataBaseCoordinator import db_query
from handlers.Verifiers import is_valid_table_name


def verify_product_exists(id, table):
    # Secure Query: Validate the table name
    if not is_valid_table_name(table):
        return False  # Return an error or handle it appropriately

    # Secure Query: Check if the ID exists in the specified table
    query = "SELECT * FROM {} WHERE name = %s;".format(table)
    results = db_query(query, (id,))

    if len(results) == 0:
        return False
    else:
        return True


def verify_id_exists(id, table):
    # Secure Query: Validate the table name
    if not is_valid_table_name(table):
        return False  # Return an error or handle it appropriately

    # Secure Query: Check if the ID exists in the specified table
    query = "SELECT * FROM {} WHERE id = %s;".format(table)
    results = db_query(query, (id,))

    if len(results) == 0:
        return False
    else:
        return True
    

def generate_random_product_id(table):
    # Generate a random ID
    random_id = random.randint(100000, 999999)

    # Check if the generated ID already exists, regenerate if necessary
    while verify_id_exists(random_id, table):
        random_id = random.randint(100000, 999999)

    return random_id


def create_product_image(id, product_photo):
    try:
        # Get the current working directory
        if os.name == "nt":
            # Get the current working directory
            current_directory = os.path.dirname(os.path.abspath(__file__)).split("\\handlers")[0]
        else:
            # Get the current working directory
            current_directory = os.path.dirname(os.path.abspath(__file__)).split("/handlers")[0]

        # Define the path for the product image directory
        product_image_directory = os.path.join(current_directory, "catalog")

        # Create the product image directory and any missing parent directories
        os.makedirs(product_image_directory, exist_ok=True)

        # Construct the full path for the product image file
        product_image_path = os.path.join(product_image_directory, f"{id}.png")

        # Check if the product image file already exists and remove it
        if os.path.exists(product_image_path):
            print("Removing existing product image file...")
            print(product_image_path)
            os.remove(product_image_path)

        # Save the product photo to the specified path
        product_photo.save(product_image_path)

    except Exception as e:
        print(e)  # Handle or log any exceptions that occur during this process


def create_product(product_name, product_description, product_price, product_category, product_quantity, product_photo):

    # check if the product already exists
    if verify_product_exists(product_name, "products"):
        return None

    # Generate a unique user id
    id = str(generate_random_product_id("products"))
    
    # Add the user to the USER table
    # Secure Query
    db_query("INSERT INTO products (id, name, description, price, category, stock) VALUES (%s, %s, %s, %s, %s, %s);",
            (id, product_name, product_description, product_price, product_category, product_quantity)
    )

    # Create a folder for the user
    create_product_image(id, product_photo)

    # Return the created user
    return id


def remove_product(id):
    # Secure Query
    query = "DELETE FROM products WHERE id = %s"
    db_query(query, (id,))


    # Get the current working directory
    directory = os.getcwd()

    # Define the path for the user's directory
    user_directory = os.path.join(directory, "catalog")

    # Create the user's directory and any missing parent directories
    if os.path.exists(os.path.join(user_directory, f"{id}.png")):
        os.remove(os.path.join(user_directory, f"{id}.png"))

    return True


def update_product_name(id, name):
    # Secure Query
    query = "UPDATE products SET name = %s WHERE id = %s"
    db_query(query, (name, id))

    return True


def update_product_description(id, description):
    # Secure Query
    query = "UPDATE products SET description = %s WHERE id = %s"
    db_query(query, (description, id))

    return True


def update_product_price(id, price):
    # Secure Query
    query = "UPDATE products SET price = %s WHERE id = %s"
    db_query(query, (price, id))

    return True


def update_product_category(id, category):
    
    # Secure Query
    query = "UPDATE products SET category = %s WHERE id = %s"
    db_query(query, (category, id))

    return True


def update_product_quantity(id, quantity):
    # Secure Query
    query = "UPDATE products SET stock = %s WHERE id = %s"
    db_query(query, (quantity, id))

    return True


def create_review(id, user_id, review, rating):
    review_id = str(generate_random_product_id("reviews"))

    # Secure Query
    query = "INSERT INTO reviews (id, product_id, user_id, rating, review) VALUES (%s, %s, %s, %s, %s);"
    db_query(query, (review_id, id, user_id, rating, review))

    return True


def set_cart_item(table_name, product_id, quantity, operation):
    # Secure Query: Validate the table name
    if not is_valid_table_name(table_name):
        return False  # Return an error or handle it appropriately

    # Secure Query: Check if the product is already in the cart
    query = "SELECT * FROM {} WHERE product_id = %s".format(table_name)
    results = db_query(query, (product_id,))

    if len(results) != 0:
        # Update the quantity
        if operation == "add":
            # Secure Query: Update the quantity
            update_query = "UPDATE {} SET quantity = quantity + %s WHERE product_id = %s".format(table_name)
        else:
            # Secure Query: Update the quantity
            update_query = "UPDATE {} SET quantity = quantity - %s WHERE product_id = %s".format(table_name)

        # Secure Query: Execute the update
        db_query(update_query, (quantity, product_id))
        return True
    else:
        # Add the product to the cart
        # Secure Query: Insert into the cart
        insert_query = "INSERT INTO {} (product_id, quantity) VALUES (%s, %s)".format(table_name)
        db_query(insert_query, (product_id, quantity))
        return True



def register_order(username, user_id, order_details, products):
    try:
        products_to_register = {}
        total_price = 0
        for product in products:
            total_price += float(product["price"]) * product["quantity"]
            products_to_register[product["product_id"]] = product["quantity"]

        order_id = str(generate_random_product_id("all_orders"))
        time = datetime.now().strftime("%d-%m-%Y %H:%M")
        
        # Register in all orders
        # Secure Query
        all_orders_query = "INSERT INTO all_orders (id, user_id, order_date) VALUES (%s, %s, %s);"
        db_query(all_orders_query, (order_id, user_id, time))

        # Register in user-specific orders table
        # Secure Query: Validate the table name
        user_orders_table = f"{username}_orders"
        if not is_valid_table_name(user_orders_table):
            return False, None

        user_orders_query = "INSERT INTO {} (id, products, total_price, shipping_address, order_date) VALUES (%s, %s, %s, %s, %s);".format(user_orders_table)
        db_query(user_orders_query, (order_id, json.dumps(products_to_register), total_price, order_details["shipping_address"], time))

        return True, order_id
    except:
        return False, None
    

def update_product_after_order(products):

    for product in products:
        product_stock = get_product_by_id(product["product_id"])["stock"]
        quantity = product["quantity"]
        if product_stock < quantity:
            return False
        # update the product quantity
        update_product_quantity(product["product_id"], product_stock - quantity)
    return True