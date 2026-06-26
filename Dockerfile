# =========================================================
# STAGE 1: builder de pswoosh_ffi (Rust + maturin)
# =========================================================
FROM python:3.11-alpine AS rust-builder

WORKDIR /build

# Dependencias de compilación del módulo Rust/Python
RUN apk add --no-cache \
    build-base \
    python3-dev \
    libffi-dev \
    linux-headers \
    musl-dev \
    cargo \
    rust \
    pkgconf \
    patchelf

RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel maturin

# Copia solo pswoosh para aprovechar caché
COPY third_party/pswoosh /build/pswoosh

WORKDIR /build/pswoosh/rust/ref0

# Copia wheel del módulo Python-Rust
RUN maturin build --release


# =========================================================
# STAGE 2: imagen final del framework
# =========================================================
FROM python:3.11-alpine
LABEL authors="Santiago Arias"

ENV FLASK_APP=flaskr
ENV FLASK_ENV=production

WORKDIR /app

COPY requirements.txt requirements.txt
COPY dockerstart.sh start.sh
COPY Crypto/py-fhe /app/Crypto/py-fhe

# Dependencias nativas del framework
RUN apk add --no-cache \
    build-base \
    python3-dev \
    libffi-dev \
    linux-headers \
    net-tools \
    wireless-tools \
    gmp-dev \
    mpfr-dev \
    mpc1-dev \
    pkgconf

# FLINT desde edge/community
RUN apk add --no-cache \
    -X https://dl-cdn.alpinelinux.org/alpine/edge/community \
    flint-dev

# Python base
RUN python -m pip install --no-cache-dir --upgrade pip

# Instala todo menos python-flint
RUN sed '/^python-flint/d' requirements.txt > requirements.noflint.txt \
 && python -m pip install --no-cache-dir -r requirements.noflint.txt

# Instala python-flint
RUN python -m pip install --no-cache-dir \
    --config-settings=setup-args="-Dflint_version_check=false" \
    python-flint~=0.8.0

# Instala py-fhe y waitress
RUN python -m pip install --no-cache-dir /app/Crypto/py-fhe \
 && python -m pip install --no-cache-dir waitress

# Copia el wheel construido en la fase builder
COPY --from=rust-builder /build/pswoosh/rust/ref0/target/wheels /tmp/pswoosh_wheels

# Instala el wheel de pswoosh_ffi
RUN python -m pip install --no-cache-dir /tmp/pswoosh_wheels/*.whl

# Copai el framework
COPY . .

EXPOSE 5000
CMD ["./start.sh"]