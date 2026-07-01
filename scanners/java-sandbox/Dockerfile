# java-sandbox for poc_forge reproducer scripts.
#
# Same posture as the other sandboxes: no network egress, read-only /repo
# bind-mount, stays alive so the host orchestrator can `docker exec` in.
# The runner harness is Python (matching the other sandboxes); it shells out
# to `java` in single-file source-code mode (`java Repro.java`, JDK 11+) so no
# separate compile step is needed.
FROM eclipse-temurin:21-jdk

ENV PYTHONDONTWRITEBYTECODE=1

# python3 for the run-reproducer harness; curl only to fetch the sqlite-jdbc
# driver at build time (build has network; runtime does not).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 curl \
    && rm -rf /var/lib/apt/lists/*

# Bundle the sqlite-jdbc driver so SQLi/RCE repros can stand up an in-process
# SQLite DB with no network and no DB server (parallels php-sandbox pdo_sqlite).
# On the classpath via CLASSPATH so `java Repro.java` picks it up.
ARG SQLITE_JDBC_VERSION=3.46.1.3
RUN curl -fsSL -o /opt/sqlite-jdbc.jar \
    "https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/${SQLITE_JDBC_VERSION}/sqlite-jdbc-${SQLITE_JDBC_VERSION}.jar"
ENV CLASSPATH=/opt/sqlite-jdbc.jar

COPY run-reproducer.py /usr/local/bin/run-reproducer
RUN chmod +x /usr/local/bin/run-reproducer

COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/entrypoint"]
