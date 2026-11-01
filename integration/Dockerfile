ARG pyver=3.11
FROM python:${pyver}-slim-trixie AS python-prepare

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/

WORKDIR /pip
COPY pyproject.toml /pip/

ARG resolution=highest
RUN uv export --no-cache --no-emit-project --no-dev --resolution="$resolution" --format=requirements.txt --output-file=requirements.txt


FROM python:${pyver}-slim-trixie AS python-hv4gha

COPY --from=python-prepare /pip/requirements.txt /pip/
COPY pyproject.toml LICENSE README.md /src/
COPY hv4gha /src/hv4gha

RUN pip install --no-cache-dir --root-user-action=ignore --requirement=/pip/requirements.txt \
 && pip install --no-cache-dir --root-user-action=ignore --no-deps /src/

COPY --chmod=755 integration/testrun.py /app/
ENTRYPOINT ["/app/testrun.py"]
