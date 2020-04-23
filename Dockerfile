FROM jupyterhub/jupyterhub:1.2

#FROM jupyterhub/jupyterhub:1.1.0
# this is NOT the most recent on 20200422, but the one Alex Barth
# asked me to use for comptability.
#RUN which python      # /usr/bin/python
#RUN python --version  # Python 2.7.17 
#RUN /opt/conda/bin/python --version # no exist

#FROM jupyterhub/jupyterhub:1.0.0
# this is the  most recent on 20190521
#RUN which python     # /opt/conda/bin/python
#RUN python --version # Python 3.6.7

# Add useful tools
RUN apt-get update && apt-get install -y vim

# Install spawner
RUN pip3 install --upgrade pip
RUN pip3 install dockerspawner==0.11.1 # most recent on 20200305, on pypi
# Still the most recent on 20200422

# Logo
COPY ./logo.png /usr/local/share/jupyter/hub/static/images/logo.png
#COPY ./favicon.ico /usr/local/share/jupyter/hub/static/images/favicon.ico

# Install out-of-the-box Dummyauthenticator from pip
RUN pip3 install jupyterhub-dummyauthenticator
# Use this like this:
# c.JupyterHub.authenticator_class = 'jupyterhub.auth.DummyAuthenticator'
# c.DummyAuthenticator.password = "rSGTs2o4qKAcZMUFDyzqqVhHLb7Q8fwtDbxcaRKl"

# Install new Authenticator

# From local files:
RUN python3 --version
COPY ./auth_package jupyterhub-vreauthenticator/
RUN cd ./jupyterhub-vreauthenticator && python3 setup.py install && cd ..
# From github:
#RUN git clone https://github.com/merretbuurman/jupyterhub-webdavauthenticator.git
#RUN cd jupyterhub-webdavauthenticator && python setup.py install && cd ..

# This is only to check if it built correctly:
#RUN python --version
RUN python3 --version
RUN python3 -c "import vreauthenticator"

# docker build -t jupyterhub_vre:20200422-1 .
# docker build -t registry-sdc.argo.grnet.gr/jupyterhub_vre:20200422-1 .
# docker push registry-sdc.argo.grnet.gr/jupyterhub_vre:20200422-1
