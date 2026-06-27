#!/bin/bash

ENV_NAME="WS-PSI-ENV"
INSTALL_PSWOOSH=false

for arg in "$@"; do
    case "$arg" in
        -pswoosh|--pswoosh)
            INSTALL_PSWOOSH=true
            ;;
        -h|--help)
            echo "Uso: ./install.sh [-pswoosh]"
            echo ""
            echo "Opciones:"
            echo "  -pswoosh, --pswoosh   Instala y compila el módulo pswoosh_ffi."
            echo "  -h, --help            Muestra esta ayuda."
            exit 0
            ;;
        *)
            echo "Opción desconocida: $arg"
            echo "Usa ./install.sh --help para ver las opciones disponibles."
            exit 1
            ;;
    esac
done

echo "### PSI Suite - Instalador de dependencias ###"
echo "Por favor, asegúrate de que este instalador se esté ejecutando en un entorno Linux con Python 3.12"
echo "ENV_NAME: $ENV_NAME"
echo "PYTHON VERSION: $(python3.12 --version)"
echo "Instalar pswoosh: $INSTALL_PSWOOSH"
echo "#############################################"

echo "Creando el entorno virtual... -> $ENV_NAME"
python3.12 -m venv "$ENV_NAME"

echo "Activando el entorno virtual..."
source "$ENV_NAME/bin/activate"

echo "Actualizando pip..."
pip install --no-cache-dir --upgrade pip

echo "Instalando dependencias de requirements.txt..."
pip install --no-cache-dir -r requirements.txt

echo "Instalando dependencia específica de BFV (py-fhe)..."
cd Crypto/py-fhe || exit 1
pip install .
cd ../.. || exit 1

echo "Instalación base completada."
echo "#############################################"

if [ "$INSTALL_PSWOOSH" = true ]; then
    echo "### Instalación del módulo pswoosh_ffi ###"

    if ! command -v cargo >/dev/null 2>&1; then
        echo "ERROR: cargo no está disponible."
        echo "Instala Rust previamente con:"
        echo "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo "Después ejecuta:"
        echo "source \"\$HOME/.cargo/env\""
        echo "y vuelve a lanzar:"
        echo "./install.sh -pswoosh"
        exit 1
    fi

    echo "Rust/Cargo detectado:"
    cargo --version

    echo "Preparando directorio third_party..."
    mkdir -p third_party

    if [ ! -d "third_party/pswoosh" ]; then
        echo "Clonando pswoosh_WS_PSI..."
        git clone https://github.com/UO265181/pswoosh_WS_PSI.git third_party/pswoosh
    else
        echo "El directorio third_party/pswoosh ya existe. Se reutilizará."
    fi

    echo "Compilando pswoosh_ffi con maturin..."
    cd third_party/pswoosh/rust/ref0 || exit 1
    maturin develop --release

    echo "Comprobando pswoosh_ffi..."
    python test_pswoosh_ffi.py

    cd ../../../.. || exit 1

    echo "Módulo pswoosh_ffi instalado correctamente."
    echo "#############################################"
fi

echo "Entorno virtual creado y dependencias instaladas."
echo "Para activar el entorno en futuras sesiones:"
echo "source $ENV_NAME/bin/activate"