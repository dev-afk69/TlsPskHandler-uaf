# Builder image: use a JDK image and run the Gradle wrapper present in /zuul
FROM eclipse-temurin:21-jdk AS builder

# Install git, unzip, and wget (used by gradle wrapper/plugins and to download wrapper jar if needed)
RUN apt-get update && apt-get install -y --no-install-recommends git unzip wget && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy the upstream zuul source tree (do not modify files under /zuul in the repository)
COPY zuul /workspace/zuul
# If the repository root has a .git, copy it into the zuul tree so Gradle/nebula plugins can access git metadata
# This build uses the repo root as context, so .git will be available to copy when present.
COPY .git /workspace/zuul/.git

WORKDIR /workspace/zuul

RUN chmod +x ./gradlew || true

# Ensure gradle wrapper jar exists. If it's missing (not in git due to .gitignore),
# download it manually from the gradle distribution mirror.
RUN if [ ! -f gradle/wrapper/gradle-wrapper.jar ]; then \
    mkdir -p gradle/wrapper && \
    wget -q -O gradle/wrapper/gradle-wrapper.jar https://services.gradle.org/distributions/gradle-wrapper-9.2.1.jar && \
    echo "Downloaded gradle wrapper jar"; \
  fi

# Pre-download gradle distribution by checking gradle version
# This ensures all dependencies are cached before the actual build
RUN ./gradlew --version || true

# Build the zuul sample distribution (skip tests to speed up builds)
RUN ./gradlew :zuul-sample:installDist -x test --no-daemon

# Runtime image
FROM eclipse-temurin:21-jre
ENV SERVER_PORT=7001
WORKDIR /opt/zuul

# Copy the installed distribution from the builder
COPY --from=builder /workspace/zuul/zuul-sample/build/install/zuul-sample /opt/zuul

# Copy non-invasive runtime config into the image so we can point Archaius to it
COPY zuul-config/zuul.properties /opt/zuul/config/zuul.properties

EXPOSE 7001
# Start the zuul sample
CMD ["/opt/zuul/bin/zuul-sample"]
