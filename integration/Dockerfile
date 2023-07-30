ARG pyver=3.11
FROM python:${pyver}-slim-bookworm

COPY pyproject.toml README.md /src/
COPY hv4gha /src/hv4gha

RUN pip install --no-cache-dir /src/

COPY --chmod=755 integration/testrun.py /app/
ENTRYPOINT ["/app/testrun.py"]
