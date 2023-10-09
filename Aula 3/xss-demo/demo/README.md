XSS Demo
========

Example application and scripts to demonstrate some XSS vulnerabilities.

The vulnerable Pyramid application (a blog where the administrator can post new
entries and were anyone can add comments) can be found in the app/
subdirectory.


This setup was tested on Debian 12 and it should work out of the box on any
recent Debian based Linux distribution (with Python 3). Setting it up on other
Operating Systems should not be a problem but the instructions need to be
adapted.

```bash
apt install virtualenv

virtualenv -p python3 venv
source venv/bin/activate

pip install -U setuptools && pip install -U pip
cd app
pip install -r dev_requirements.txt
python setup.py develop
```

Now you can start the application:

```bash
pserve development.ini
```

and access it in your browser on http://localhost:6543 (if you are running the app inside a container, you need to access using the container's IP (`lxc list`))


Running
-------

The application is a simple blog where the Administrator can publish new
blogposts and anyone can add comments to the posts. There is a search function
that does nothing except show a XSS vulnerability.

Several blogposts and comments are set up on application startup out of the
box.  The *database* (just in memory) is reset on every application start. The
secret key used to sign the cookies is also reset on every application start.

### Adding a comment

To add a comment simply click on any of the blogposts and use the form at the bottom. The comments will be displayed in chronological order.

### Logging in / Adding a post

To add a blogpost you need to log in with user *Administrator* and password *top-secret* .

Then click on the **Add Post** link in the menu and fill out the form.
