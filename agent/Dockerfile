FROM node:22-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl bash \
  && rm -rf /var/lib/apt/lists/*

# Install Foundry (cast)
RUN curl -L https://foundry.paradigm.xyz | bash \
  && /root/.foundry/bin/foundryup

ENV PATH="/root/.foundry/bin:${PATH}"
WORKDIR /app

COPY agent/governance_agent.mjs /app/agent/governance_agent.mjs
COPY agent/manager_api.mjs /app/agent/manager_api.mjs
COPY agent/healthcheck.mjs /app/agent/healthcheck.mjs
COPY agent/policy.example.json /app/agent/policy.example.json
COPY agent/state/.gitkeep /app/agent/state/.gitkeep

CMD ["node", "/app/agent/governance_agent.mjs"]
