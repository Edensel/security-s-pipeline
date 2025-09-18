FROM aquasec/trivy:latest

# Install additional tools
RUN apk add --no-cache \
    bash \
    curl \
    jq \
    python3 \
    py3-pip

# Create necessary directories
RUN mkdir -p /etc/trivy /usr/local/bin/scripts

# Create scanning script
RUN echo '#!/bin/bash\n\
if [ "$1" = "server" ]; then\n\
    trivy server --listen 0.0.0.0:4954\n\
else\n\
    trivy "$@"\n\
fi' > /usr/local/bin/scripts/scan.sh && \
    chmod +x /usr/local/bin/scripts/scan.sh

EXPOSE 4954

ENTRYPOINT ["/usr/local/bin/scripts/scan.sh"]
CMD ["server"]