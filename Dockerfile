FROM node:26-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1
# Application files stay root-owned and read-only to the runtime user; only the data directory,
# /var/lib/uptime-goblin, is writable. A volume still mounted at /app/data, where Orbit kept its
# data before the rename to Uptime Goblin, is used while it is the only one with data, with a notice
# at every start (lib/legacy-names.mjs, containerDataDirectory).
# A larger libuv pool keeps one slow DNS lookup from delaying every other request.
# Supervised (GOBLIN_SUPERVISED=1, and --supervised in CMD below), Uptime Goblin exits 0 only after
# a stop signal and 78 when it refuses to start, and checks its memory, CPU and process limits.
ENV NODE_ENV=production HOST=0.0.0.0 PORT=4317 GOBLIN_DATA_DIR=/var/lib/uptime-goblin \
  UV_THREADPOOL_SIZE=16 GOBLIN_SUPERVISED=1
WORKDIR /app
# The pinned base predates this Debian security update. Keep the exact package version
# explicit; an unavailable version fails the build rather than silently using an older one.
RUN apt-get update && apt-get install -y --no-install-recommends libpcre2-8-0=10.42-1+deb12u2 \
  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force \
    # Runtime uses node directly. Package managers and their dependency trees are build tools.
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /opt/yarn-* /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/yarn /usr/local/bin/yarnpkg /usr/local/bin/pnpm /usr/local/bin/pnpx
COPY server.mjs LICENSE ./
COPY lib ./lib
COPY public ./public
COPY docs ./docs
COPY deploy/allowed_signers deploy/manifest.txt ./deploy/
# Fail the build when a file listed in deploy/manifest.txt did not reach the image (for example
# a new module that .dockerignore still excludes).
RUN node -e "const fs=require('node:fs');const missing=fs.readFileSync('deploy/manifest.txt','utf8').split('\n').filter(l=>l&&!l.startsWith('#')).filter(f=>!fs.statSync(f,{throwIfNoEntry:false})?.isFile());if(missing.length){console.error('Missing from the image: '+missing.join(', '));process.exit(1)}" \
  && chmod -R u=rwX,go=rX /app/package.json /app/package-lock.json /app/server.mjs /app/lib /app/public /app/docs /app/deploy /app/LICENSE \
  && mkdir -p /var/lib/uptime-goblin && chown node:node /var/lib/uptime-goblin \
  && chmod 700 /var/lib/uptime-goblin
USER node
EXPOSE 4317
VOLUME ["/var/lib/uptime-goblin"]
# /health answers 200 without signing in. The start period covers a slow first start.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 CMD ["node", "lib/healthcheck.mjs"]
# --supervised keeps the limits check on whatever the container's environment says: docker run -e
# or a Compose override can change GOBLIN_SUPERVISED, not this command line (lib/resource-limits.mjs).
CMD ["node", "server.mjs", "--supervised"]
