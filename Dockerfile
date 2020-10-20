FROM jupyterhub/jupyterhub:1.2
# Digest: 44111725d95b
# That digest is not available anymore on 20200918.
# It was created 2020-03-02T09:29:11.732094618Z
# I strongly assume it is commit 1bdc66c
# (anyway, it must be this or later, but before 08eee93)
# https://github.com/jupyterhub/jupyterhub/commit/1bdc66c75b786c11fb24c13eb281a0dd61fa0a92
#
# The tag :1.2 now corresponds to digest cba38d5ccf6a. 
# In future, ideally write the git commit into here for later debugging!
#
#root@d8dfbff8b600:/usr/local/lib/python3.6/dist-packages/jupyterhub# grep -r 'require(\[\"jquery\"' /usr/
#...
#/usr/local/share/jupyterhub/static/js/home.js:require(["jquery", "moment", "jhapi"], #function(
# So it is definitely AFTER this commit happened: 1bdc66c
# https://github.com/jupyterhub/jupyterhub/commit/1bdc66c75b786c11fb24c13eb281a0dd61fa0a92
# I will assume it is this commit, because the 2-3 ones afterwards are only non-python stuff I think.

# And BEFORE 08eee93
https://github.com/jupyterhub/jupyterhub/commit/08eee9309ef5b6ee6a707b117080b0d99d9989c5
# Because:
root@d8dfbff8b600:/usr/local/lib/python3.6/dist-packages/jupyterhub# vi _version.py


#RUN which python3     # /usr/bin/python3
#RUN python3 --version # Python 3.6.9

# Add useful tools (wget for the health check)
RUN apt-get update && apt-get install -y vim wget

# Install spawner
RUN pip3 install --upgrade pip
RUN pip3 install dockerspawner==0.11.1 # most recent on 20200422, on pypi

# Logo
COPY ./logo.png ./archive/
COPY ./dkrz_favicon.ico ./archive/favicon.ico

# Useful for reference:
# RUN pwd # /srv/jupyterhub
COPY ./Dockerfile ./archive/
COPY ./docker-compose.yml ./archive/
COPY ./jupyterhub_config.py ./archive/
COPY ./healthcheck_jupyterhub.sh ./archive/
COPY ./ADAPTED_start.sh ./archive/
# ADAPTED_start.sh is for running as uid 33
RUN echo `date` > ./archive/now.txt
RUN ls -lpah ./archive

# Install out-of-the-box Dummyauthenticator from pip
RUN pip3 install jupyterhub-dummyauthenticator
# Use this like this:
# c.JupyterHub.authenticator_class = 'jupyterhub.auth.DummyAuthenticator'
# c.DummyAuthenticator.password = "change-me"

# Install custom VREAuthenticator

# From local files:
COPY ./auth_package jupyterhub-vreauthenticator/
RUN cd ./jupyterhub-vreauthenticator && python3 setup.py install && cd ..
# From github: # TODO
#RUN git clone https://github.com/merretbuurman/jupyterhub-webdavauthenticator.git
#RUN cd jupyterhub-webdavauthenticator && python setup.py install && cd ..

# This is only to check if it built correctly:
RUN python3 -c "import vreauthenticator"

# docker build -t jupyterhub_vre:20200428 .
# docker build -t registry-sdc.argo.grnet.gr/jupyterhub_vre:20200428 .
# docker push registry-sdc.argo.grnet.gr/jupyterhub_vre:20200428
