from ToDoWebsite import create_app 
# we were able to import this as it was a python package coz we declared __init__.py file in it

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)