from website import create_app
from functions import functions 

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
    functions.check_database_table_exists("users")
