FROM python:3.13-alpine

LABEL org.opencontainers.image.title="Arrmor" \
      org.opencontainers.image.description="Read-only allow-list proxy between Seerr and Sonarr/Radarr" \
      org.opencontainers.image.source="https://github.com/Makario1337/Arrmor" \
      org.opencontainers.image.licenses="GPL-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ARRMOR_PORT=8080

# openssl is only used for ARRMOR_TLS_SELF_SIGNED; /certs is where the
# generated certificate lives (mount a volume there to keep it).
RUN apk upgrade --no-cache \
 && apk add --no-cache openssl \
 && mkdir /certs \
 && chown 65534:65534 /certs

COPY arrmor.py /app/arrmor.py

USER 65534:65534
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-I", "/app/arrmor.py", "--healthcheck"]

# -I: isolated mode (ignores PYTHON* variables and the working directory),
# -u: unbuffered logs (PYTHONUNBUFFERED is ignored in isolated mode)
ENTRYPOINT ["python", "-I", "-u", "/app/arrmor.py"]
