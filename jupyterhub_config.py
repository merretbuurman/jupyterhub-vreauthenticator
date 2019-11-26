# Configuration file for Jupyter Hub
import os

c = get_config()


###
### Get all env variables
###

##
## Have to be set:
DOCKER_JUPYTER_IMAGE = os.environ['DOCKER_JUPYTER_IMAGE']
DOCKER_NETWORK_NAME = os.environ['DOCKER_NETWORK_NAME']

##
## Optional, have defaults:
CONTAINER_PREFIX = os.environ.get('CONTAINER_PREFIX', 'jupyter')
MEMORY_LIMIT = os.environ.get('MEMORY_LIMIT', '2G')
HUB_IP = os.environ.get('HUB_IP', 'hub')
RUN_AS_USER = os.environ.get('RUN_AS_USER', None)
RUN_AS_GROUP = os.environ.get('RUN_AS_GROUP', None)
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')
ADMIN_PW = os.environ.get('ADMIN_PW', None)
WHITELIST_AUTH = os.environ.get('WHITELIST_AUTH', None)
WHITELIST_WEBDAV = os.environ.get('WHITELIST_WEBDAV', None)


##
## Memory limits
## https://github.com/jupyterhub/dockerspawner#memory-limits
c.Spawner.mem_limit = MEMORY_LIMIT

##
## spawn with Docker
c.JupyterHub.spawner_class = 'dockerspawner.DockerSpawner'

##
## Notebook Directory
## TODO: What is this setting good for?
## TODO: Do we really want to allow setting this from env?
##
## Explicitly set notebook directory because we'll be mounting a host volume to
## it.  Most jupyter/docker-stacks *-notebook images run the Notebook server as
## user `jovyan`, and set the notebook directory to `/home/jovyan/work`.
## We follow the same convention.
notebook_dir = os.environ.get('DOCKER_NOTEBOOK_DIR') or '/home/jovyan/work'
c.DockerSpawner.notebook_dir = notebook_dir

##
## Mount the user directory
## We mount the <username>_sync directory, which is the synchronizer target directory!
## We mount it to a subdirectory of the Notebook directory (so that the sync dir does not get
## crowded with weird Jupyter stuff...
##)
## TODO: Where does username come from?
##
c.DockerSpawner.volumes = {
  '/mnt/data/jupyterhub-user/jupyterhub-user-{username}': notebook_dir
}

##
## Which docker image to be spawned
c.DockerSpawner.image = DOCKER_JUPYTER_IMAGE

##
## Prefix for the container's names:
c.DockerSpawner.prefix = CONTAINER_PREFIX

##
## WebDAVAuthenticator
c.JupyterHub.authenticator_class = 'webdavauthenticator.WebDAVAuthenticator'

##
## Set the log level by value or name.
c.JupyterHub.log_level = LOG_LEVEL
if LOG_LEVEL == 'DEBUG':
  c.DockerSpawner.debug = True


##
## Set whitelists for users
## TODO Do we want to use this?
#c.Authenticator.whitelist = whitelist = set()
c.Authenticator.admin_users = admin = set()

##
## Enable passing env variables to containers from the 
## authenticate-method (which has the login form...)
c.Authenticator.enable_auth_state = True


join = os.path.join
here = os.path.dirname(__file__)

c.JupyterHub.port = 443

# ssl config
ssl = join(here, 'ssl')
keyfile = join(ssl, 'ssl.key')
certfile = join(ssl, 'ssl.cert')
if os.path.exists(keyfile):
    c.JupyterHub.ssl_key = keyfile
if os.path.exists(certfile):
    c.JupyterHub.ssl_cert = certfile

##
## Logo    
c.JupyterHub.logo_file = "/usr/local/share/jupyter/hub/static/images/sdn.png"


##
## White lists for authentication and WebDAV servers:
white_auth = [
    "https://b2drop.eudat.eu/remote.php/webdav",
    "https://dox.ulg.ac.be/remote.php/webdav",
    "https://dox.uliege.be/remote.php/webdav",
    "https://dummy",
]

white_webdav = [
    "https://b2drop.eudat.eu/remote.php/webdav",
    "https://dox.ulg.ac.be/remote.php/webdav",
    "https://dox.uliege.be/remote.php/webdav",
    "https://dummy",
]

'''
Helper to parse whitelisted servers, add the protocol to
them (https), and if http is allowed, also allow https.
'''
def add_to_whitelist(env_value_string, whitelist):
  # Allow comma separated list also with spaces:
  urls = env_value_string.split(',')
  for url in urls:
    url = url.strip()

    # If no protocol given, assume https:
    if not str.startswith(url, 'http'):
      url = 'https://%s' % url

    # Append:
    whitelist.append(url)

    # Always allow https:
    if str.startswith(url, 'http:'):
      whitelist.append(url.replace('http:', 'https:'))

if WHITELIST_AUTH is not None and isinstance(WHITELIST_AUTH, str):
  add_to_whitelist(WHITELIST_AUTH, white_auth)

if WHITELIST_WEBDAV is not None and isinstance(WHITELIST_WEBDAV, str):
  add_to_whitelist(WHITELIST_WEBDAV, white_webdav)

c.WebDAVAuthenticator.allowed_auth_servers = white_auth 
c.WebDAVAuthenticator.allowed_webdav_servers = white_webdav

##
## Set admin password
if ADMIN_PW is not None:
  c.WebDAVAuthenticator.admin_pw = ADMIN_PW

#######################
## Docker networking ##
#######################

##
## Pass the IP where the instances can access the JupyterHub instance
## The docker instances need access to the Hub, so the default loopback port doesn't work:
##from jupyter_client.localinterfaces import public_ips
##c.JupyterHub.hub_ip = public_ips()[0]
## Instead, containers will access hub by container name on the Docker network
c.JupyterHub.hub_ip = HUB_IP

##
## Pass the network name as argument to spawned containers
c.DockerSpawner.extra_host_config = { 'network_mode': DOCKER_NETWORK_NAME }

################
## Login form ##
################

##
## Custom login form
c.WebDAVAuthenticator.custom_html = """<form action="/hub/login?next=" method="post" role="form">
  <div class="auth-form-header">
    Sign in
  </div>
  <div class='auth-form-body'>

    <p>SeaDataCloud Virtual Research Environment<p>
    <p>Jupyterhub for DIVAnd</p>

    <div id="form_elements" style="display: none" >
        <label for="username_input">WebDAV username:</label>
        <input
          id="username_input"
          type="text"
          autocapitalize="off"
          autocorrect="off"
          class="form-control"
          name="username"
          val=""
          tabindex="1"
          autofocus="autofocus"
        />
        <label for='password_input'>WebDAV password:</label>
        <input
          type="password"
          class="form-control"
          name="password"
          id="password_input"
          tabindex="2"
        />

        <input
          type="text"
          class="form-control"
          name="token"
          id="token_input"
          style="display: none"
        />

        <label for='webdav_url_input'>WebDAV URL:</label>

        <input
          type="text"
          class="form-control"
          name="webdav_url"
          id="webdav_url_input"
          xstyle="display: none"
          value = "https://b2drop.eudat.eu/remote.php/webdav"
        />


        <input
          type="submit"
          id="login_submit"
          class='btn btn-jupyter'
          value='Sign In'
          tabindex="3"
        />
    </div>
  </div>
</form>
<script>

function parse_query_string(query) {
  var vars = query.split("&");
  var query_string = {};
  for (var i = 0; i < vars.length; i++) {
    var pair = vars[i].split("=");
    // If first entry with this name
    if (typeof query_string[pair[0]] === "undefined") {
      query_string[pair[0]] = decodeURIComponent(pair[1]);
      // If second entry with this name
    } else if (typeof query_string[pair[0]] === "string") {
      var arr = [query_string[pair[0]], decodeURIComponent(pair[1])];
      query_string[pair[0]] = arr;
      // If third or later entry with this name
    } else {
      query_string[pair[0]].push(decodeURIComponent(pair[1]));
    }
  }
  return query_string;
}


// substitute username and token from query string if provided
// and submit form for login.

var query = window.location.search.substring(1);
var qs = parse_query_string(query);

if (qs.username) {
  document.getElementById("username_input").value  = qs.username;
}

if (qs.password) {
   document.getElementById("password_input").value  = qs.password;
}

if (qs.webdav_url) {
   document.getElementById("webdav_url_input").value  = qs.webdav_url;
}

if (qs.token) {
   document.getElementById("token_input").value  = qs.token;
   document.getElementsByTagName("form")[0].submit();
}
else {
  document.getElementById("form_elements").style.display = "block"
}

</script>


"""
