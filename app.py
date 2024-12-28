import os
import re
from flask import Flask, request, abort, render_template, current_app
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import mariadb

TABLE_NAME = "test"
FUNCTION_NAME = "uuid_v4"
MAX_ID_LENGTH = 32
MAX_URL_LENGTH = 512

id_regex = re.compile(r"^[a-zA-Z0-9\$\-\_\.\!\*\'\(\)\,]{1," + re.escape(str(MAX_ID_LENGTH)) + r"}$")
url_regex = re.compile(
  r'^https?://'  # http:// or https:// protocol
  r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
  r'localhost|'  # localhost...
  r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
  r'(?::\d+)?'  # optional port
  r'(?:/?|[/?]\S+)$', re.IGNORECASE)

app = Flask(__name__)
auth = HTTPBasicAuth()

http_users = {
    os.environ.get("HTTP_USER") or "test": generate_password_hash(os.environ.get("HTTP_PASS") or "test"),
}
db_host = os.environ.get("DB_HOST") or "localhost"
db_port = os.environ.get("DB_PORT") or "3306"
db_user = os.environ.get("DB_USER") or "test"
db_pass = os.environ.get("DB_PASS") or "test"
db_name = os.environ.get("DB_NAME") or "test"
dbconnector = None
db = None
db_init = False

def db_connected():
  if not db_init:
    return False
  try:
      dbconnector.ping()
  except:
      return False
  return True

def db_disconnect():
  dbconnector.close()
  db_init = False

def db_connect():
  global dbconnector
  global db
  global db_init
  if not db_connected():
    try:
      dbconnector = mariadb.connect(
        user=db_user,
        password=db_pass,
        host=db_host,
        port=int(db_port),
        database=db_name,
        autocommit=True
      )
    except mariadb.Error as e:
      print(f"Error connecting to MariaDB Platform: {e}")
      return False
    else:
      db = dbconnector.cursor()
      db_init = True
  return True

def db_exec(*args):
  if db_connect():
    try:
      db.execute(*args)
      return list(db.fetchall())
    except mariadb.Error as e:
      for e_msg in e.args:
        if e_msg == "Cursor doesn't have a result set":
          return list()
      print(f"Error while executing MariaDB SQL Query: {e}")
      raise e from None
  raise mariadb.Error(f"Can't connect to server on '{db_host}'")

def check_missing_table_or_function():
  return len(db_exec(f"SHOW TABLES LIKE '{TABLE_NAME}'")) == 0 or len(db_exec(f"SHOW FUNCTION STATUS LIKE '{FUNCTION_NAME}'")) == 0

def get_redirects():
  return db_exec(f"SELECT * FROM {TABLE_NAME} ORDER BY id")

def resp_suc(msg):
  return {'result': "success", 'message': msg}

def resp_err(msg):
  return {'result': "error", 'message': msg}

def db_check(func):
  def inner(*args, **kwargs):
    if not db_connect(): return render_template('db_error.html', database_name=db_name, database_user=db_user)
    elif check_missing_table_or_function(): return render_template('db_init.html', database_name=db_name, table_name=TABLE_NAME, function_name=FUNCTION_NAME)
    else: return func(*args, **kwargs)
  return inner

def validate_id(id):
  return id is not None and id_regex.search(id) is not None

def validate_url(url):
  return url is not None and url_regex.search(url) is not None

@auth.verify_password
def verify_password(username, password):
  if username in http_users and check_password_hash(http_users.get(username), password):
    return username

@app.route('/admin/config', methods=['POST'])
@auth.login_required
def config():
  try:
    if not db_connect(): return resp_err("Database connection could not be established.")
    req = request.json
    ks = req.keys()
    if 'action' not in ks:
      return resp_err("No action was requested.")
    if req['action'] == "init":
      if not check_missing_table_or_function(): return resp_err("Database is already initialized.")
      db_exec(f"CREATE TABLE IF NOT EXISTS {TABLE_NAME} (id VARCHAR({max(MAX_ID_LENGTH, 32)}) NOT NULL, url VARCHAR({MAX_URL_LENGTH}) NOT NULL, new_tab BOOLEAN NOT NULL, PRIMARY KEY (id)) ENGINE = InnoDB")
      db_exec(f"CREATE FUNCTION IF NOT EXISTS {FUNCTION_NAME}() RETURNS CHAR(32) BEGIN RETURN LOWER(CONCAT(HEX(RANDOM_BYTES(4)), HEX(RANDOM_BYTES(2)), '4', SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3), HEX(FLOOR(ASCII(RANDOM_BYTES(1)) / 64) + 8), SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3), hex(RANDOM_BYTES(6)))); END;")
      return resp_suc("Database is now initialized and ready.") if not check_missing_table_or_function() else resp_err("Database could not be initialized.")
    if req['action'] == "new":
      if 'url' not in ks or 'new_tab' not in ks: return resp_err("At least one of the required arguments 'url' and 'new_tab' is missing in the request.")
      if 'id' in ks and not validate_id(req['id']): return resp_err(f"ID is not in a valid format (must contain only letters, numbers or the following chars $-_.!*'() and be max {MAX_ID_LENGTH} characters long).")
      if not validate_url(req['url']) or len(req['url']) > MAX_URL_LENGTH: return resp_err(f"URL is not in a valid format (must be a valid url and max {MAX_URL_LENGTH} characters long).")
      if req['new_tab'] not in [0, 1]: return resp_err("Argument new_tab is not in a valid format (must be an integer with value 0 or 1)")
      if 'id' in ks:
        if len(db_exec(f"SELECT id FROM {TABLE_NAME} WHERE id = ?", (req['id'],))) > 0: return resp_err(f"ID '{req['id']}' already exists.")
        else: id = db_exec(f"INSERT INTO {TABLE_NAME} VALUES(?, ?, ?) RETURNING id", (req['id'], req['url'], req['new_tab']))[0][0]
      else: id = db_exec(f"INSERT INTO {TABLE_NAME} VALUES({FUNCTION_NAME}(), ?, ?) RETURNING id", (req['url'], req['new_tab']))[0][0]
      return resp_suc(f"Added new redirect with id '{id}'.")
    if req['action'] == "edit":
      if 'old_id' not in ks or 'new_id' not in ks or 'url' not in ks or 'new_tab' not in ks: return resp_err("At least one of the required arguments 'old_id', 'new_id', 'url' and 'new_tab' is missing in the request.")
      if not validate_id(req['new_id']): return resp_err(f"ID is not in a valid format (must contain only letters, numbers or the following chars $-_.!*'() and be max {MAX_ID_LENGTH} characters long).")
      if not validate_url(req['url']) or len(req['url']) > MAX_URL_LENGTH: return resp_err(f"URL is not in a valid format (must be a valid url and max {MAX_URL_LENGTH} characters long).")
      if req['new_tab'] not in [0, 1]: return resp_err("Argument new_tab is not in a valid format (must be an integer with value 0 or 1)")
      if req['old_id'] != req['new_id'] and len(db_exec(f"SELECT id FROM {TABLE_NAME} WHERE id = ?", (req['new_id'],))) > 0: return resp_err(f"ID '{req['new_id']}' already exists.")
      db_exec(f"UPDATE {TABLE_NAME} SET id = ?, url = ?, new_tab = ? WHERE id = ?", (req['new_id'], req['url'], req['new_tab'], req['old_id']))
      return resp_suc(f"Changed redirect with id '{req['new_id']}'.")
    if req['action'] == "delete":
      if 'id' not in ks: return resp_err("The required argument 'id' is missing in the request.")
      if len(db_exec(f"SELECT id FROM {TABLE_NAME} WHERE id = ?", (req['id'],))) == 0: return resp_err(f"ID '{req['id']}' does not exist.")
      db_exec(f"DELETE FROM {TABLE_NAME} WHERE id = ?", (req['id'],))
      return resp_suc(f"Deleted redirect with id '{req['id']}'")
    return resp_err("Requested action is not supported.")
  except:
    return resp_err(f"Internal server error.")

@app.route('/<path:id>', methods=['GET'])
def redir(id):
  res = db_exec(f"SELECT id, url, new_tab FROM {TABLE_NAME} WHERE id = ?", (id,))
  if len(res) == 0: abort(404)
  url = res[0][1]
  new_tab = res[0][2]
  if new_tab: return render_template('redir_new_tab.html', url=url)
  else: return render_template('redir_same_tab.html', url=url)

@app.route('/', endpoint='index')
@auth.login_required
@db_check
def index():
  return render_template('redir_same_tab.html', url="/admin/home")

@app.route('/admin/home', endpoint='home')
@auth.login_required
@db_check
def home():
  redirects = get_redirects()
  return render_template('home.html', redirects=redirects)

@app.route('/admin/add', endpoint='add')
@auth.login_required
@db_check
def add():
  return render_template('add.html', max_url_len=MAX_URL_LENGTH, max_id_len=MAX_ID_LENGTH)

@app.route('/admin/edit', endpoint='edit')
@auth.login_required
@db_check
def edit():
  redirects = get_redirects()
  return render_template('edit.html', redirects=redirects, max_url_len=MAX_URL_LENGTH, max_id_len=MAX_ID_LENGTH)

@app.route('/admin/delete', endpoint='delete')
@auth.login_required
@db_check
def delete():
  redirects = get_redirects()
  return render_template('delete.html', redirects=redirects)

@app.route('/admin/logo.png')
def logo():
  return current_app.send_static_file('logo.png')

@app.route('/favicon.ico')
def favicon():
  return current_app.send_static_file('favicon.ico')

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port="81")