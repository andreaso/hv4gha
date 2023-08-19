# hadolint global ignore=DL3013

ARG pyver=3.11
FROM python:${pyver}-slim-bookworm AS python-prepare

RUN pip install --no-cache-dir poetry

WORKDIR /pip
COPY pyproject.toml poetry.lock /pip/

RUN poetry export --without-hashes --format=requirements.txt --output=constraints.txt


FROM python:${pyver}-slim-bookworm AS python-hv4gha

COPY --from=python-prepare /pip/constraints.txt /src/
COPY pyproject.toml README.md /src/
COPY hv4gha /src/hv4gha

ARG pip_extra=""
RUN pip install --no-cache-dir ${pip_extra} /src/

COPY --chmod=755 integration/testrun.py /app/
ENTRYPOINT ["/app/testrun.py"]
