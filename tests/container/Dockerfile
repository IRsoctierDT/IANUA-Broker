# Test-only image for the real-container sandbox test (CI, Linux). The scanner
# under test still requires the BUILT image's immutable id (sha256:...), so the
# mutable base tag here never reaches a scan.
FROM python:3.12-alpine
COPY _stdio_mcp_server.py /srv/server.py
USER 65534:65534
ENTRYPOINT ["python", "-u", "/srv/server.py", "probe"]
