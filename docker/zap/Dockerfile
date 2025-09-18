FROM ghcr.io/zaproxy/zaproxy:stable

# Install additional dependencies
USER root
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-venv \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create directories and set permissions
RUN mkdir -p /zap/scripts /zap/policies /zap/config && \
    chown -R zap:zap /zap

# Switch to zap user
USER zap

# Set up Python virtual environment
RUN python3 -m venv /zap/venv
ENV PATH="/zap/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt /zap/
RUN . /zap/venv/bin/activate && \
    pip install --no-cache-dir -r /zap/requirements.txt

# Set working directory
WORKDIR /zap

# Configure ZAP
ENV ZAP_PORT=8080
ENV PATH=$PATH:/zap/

EXPOSE 8080

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:$ZAP_PORT/ || exit 1

# Create entrypoint script
RUN echo '#!/bin/bash\n. /zap/venv/bin/activate\nzap.sh "$@"' > /zap/scripts/entrypoint.sh && \
    chmod +x /zap/scripts/entrypoint.sh

ENTRYPOINT ["/zap/scripts/entrypoint.sh"]
CMD ["-h"]