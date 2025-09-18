FROM sonarqube:9.9-community

# Install curl and download plugins
USER root
RUN apt-get update && \
    apt-get install -y curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER sonarqube
RUN mkdir -p /opt/sonarqube/extensions/plugins/temp && \
    cd /opt/sonarqube/extensions/plugins/temp && \
    curl -sSLO https://github.com/SonarSecurityCommunity/dependency-check-sonar-plugin/releases/download/2.0.8/sonar-dependency-check-plugin-2.0.8.jar && \
    mv *.jar .. && \
    rm -rf /opt/sonarqube/extensions/plugins/temp

# Set environment variables
ENV SONAR_WEB_JAVAOPTS="-Xmx2G -Xms1G -XX:+HeapDumpOnOutOfMemoryError"
ENV SONAR_CE_JAVAOPTS="-Xmx2G -Xms1G -XX:+HeapDumpOnOutOfMemoryError"
ENV SONAR_SEARCH_JAVAOPTS="-Xmx2G -Xms1G -XX:+HeapDumpOnOutOfMemoryError"

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9000/api/system/status || exit 1