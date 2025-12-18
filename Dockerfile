# For meta-repo builds; pins base image
FROM ghcr.io/project-unisonos/unison-common-wheel:latest AS common_wheel
FROM python:3.12-slim

ARG REPO_PATH="."
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY ${REPO_PATH}/constraints.txt ./constraints.txt
COPY ${REPO_PATH}/requirements.txt ./requirements.txt
COPY --from=common_wheel /tmp/wheels /tmp/wheels
RUN pip install --no-cache-dir -c ./constraints.txt /tmp/wheels/unison_common-*.whl \
    && pip install --no-cache-dir -c ./constraints.txt -r requirements.txt

COPY ${REPO_PATH}/schemas ./schemas
COPY ${REPO_PATH}/manifests ./manifests
COPY ${REPO_PATH}/registries ./registries
COPY ${REPO_PATH}/skill_packs ./skill_packs
COPY ${REPO_PATH}/src ./src
COPY ${REPO_PATH}/tests ./tests
COPY ${REPO_PATH}/config.example.yaml ./config.example.yaml

ENV PYTHONPATH=/app/src
EXPOSE 8102

# Safe default: loopback-only binding. For container networking, front with Envoy/Nginx and keep this private.
CMD ["python", "src/server.py"]
