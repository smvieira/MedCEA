# Optional: bake VS Code and the collaboration extension into the notebook image
# instead of installing them into each user's home on first start.
#
# The deploy script works without this — it installs into the persistent home
# volume via a postStart hook, so only the first launch is slow. Build this when
# you would rather pay the cost once, at build time, for every user.
#
#   microk8s enable registry
#   docker build -t localhost:32000/cea-workbench:1 -f infra/workbench.Dockerfile infra/
#   docker push localhost:32000/cea-workbench:1
#   # then in config.env:
#   WORKBENCH_IMAGE="localhost:32000/cea-workbench:1"
FROM quay.io/jupyter/scipy-notebook:latest

USER root
RUN curl -fsSL https://code-server.dev/install.sh | sh -s -- --method=standalone --prefix=/usr/local
USER ${NB_UID}

RUN pip install --no-cache-dir \
      jupyter-collaboration \
      jupyter-vscode-proxy \
      paho-mqtt \
      psycopg2-binary \
 && fix-permissions "${CONDA_DIR}" && fix-permissions "/home/${NB_USER}"
