# Build stage.
#
# The corpus is cloned here, at image build time, rather than copied from the
# build context. Copying would bake in whatever happens to sit in the local
# checkout — an uninitialised or drifted submodule silently produces a wrong
# image — while cloning makes the corpus state an explicit build argument.
#
# It is deliberately NOT cloned at container start: that would need network and
# git at runtime, would break when GitHub is unreachable, and would let two runs
# of the same image answer differently. A given tag answers from a given corpus.
FROM golang:1.26-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change does not refetch the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# CGO off and a stripped binary: the runtime stage has no libc to link against.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
        -o /out/mcp-misp-galaxy ./cmd/mcp-misp-galaxy

# Corpus stage, separate so a source change does not re-clone 50k files.
FROM alpine/git:latest AS corpus

# Empty means the tip of the default branch. Pass the commit the parent
# repository pins to get the same corpus the local checkout uses:
#   --build-arg CORPUS_REF=$(git -C data/misp-galaxy rev-parse HEAD)
ARG CORPUS_REF=""
ARG CORPUS_URL="https://github.com/MISP/misp-galaxy.git"

WORKDIR /corpus
RUN set -eux; \
    if [ -n "$CORPUS_REF" ]; then \
        # Fetch just that commit: the full history is large and useless here.
        git init -q repo; \
        git -C repo remote add origin "$CORPUS_URL"; \
        git -C repo fetch -q --depth 1 origin "$CORPUS_REF"; \
        git -C repo checkout -q FETCH_HEAD; \
    else \
        git clone -q --depth 1 "$CORPUS_URL" repo; \
    fi; \
    # Record what was actually checked out, so the runtime stage reports the
    # resolved commit rather than the possibly-empty argument.
    git -C repo rev-parse HEAD > /corpus/REF; \
    # Keep only what the loader reads.
    mkdir -p /corpus/out; \
    cp -r repo/clusters repo/galaxies /corpus/out/; \
    rm -rf repo

# Runtime stage.
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=build /out/mcp-misp-galaxy /app/mcp-misp-galaxy
COPY --from=corpus /corpus/out /app/data/misp-galaxy
# There is no .git in the image, so this file is the only provenance a result
# can carry. It sits inside the corpus directory, which is what the server
# reads — and what a mounted volume would replace, hence GALAXY_CORPUS_REF as
# an override.
COPY --from=corpus /corpus/REF /app/data/misp-galaxy/CORPUS_REF

ENV GALAXY_ROOT=/app \
    GALAXY_TRANSPORT=http \
    GALAXY_ADDR=:8090

EXPOSE 8090
USER nonroot:nonroot

# -no-sync is redundant (there is no repository to sync) but explicit: it
# documents that this image never moves its data.
ENTRYPOINT ["/app/mcp-misp-galaxy", "-no-sync"]
