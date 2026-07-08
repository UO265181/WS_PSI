# WS_PSI - Integración de SWOOSH

Este repositorio contiene la integración del protocolo **SWOOSH** dentro del framework **WS_PSI**.  
WS_PSI es un servicio web basado en Flask que permite levantar nodos, exponer una API REST y utilizar una interfaz gráfica para probar protocolos criptográficos en un entorno distribuido.

En este trabajo se ha incorporado SWOOSH como un esquema de intercambio de claves no interactivo resistente frente a amenazas cuánticas. La integración incluye distintos backends de ejecución:

- `BackendFlint`: implementación Python apoyada en `python-flint`.
- `BackendNTTBasic`: implementación experimental basada en NTT/FTT.
- `BackendNTTBasic2`: versión optimizada de `BackendNTTBasic`.
- `BackendRust`: integración nativa mediante Rust y FFI, basada en `pswoosh`.

## Requisitos

La instalación se ha probado principalmente en Ubuntu. Las versiones utilizadas durante el desarrollo fueron:

- Python 3.12.3
- Rust / rustup 1.29.0
- Docker 29.4.3

## Instalación del framework

### 1. Clonar el repositorio principal

```bash
git clone https://github.com/UO265181/WS_PSI.git
cd WS_PSI
```

### 2. Crear y activar el entorno virtual

```bash
python3 -m venv WS-PSI-ENV
source WS-PSI-ENV/bin/activate
```

### 3. Instalar dependencias Python

```bash
pip install -r requirements.txt
```

### 4. Instalar el módulo local `py-fhe`

```bash
cd Crypto/py-fhe
pip install .
cd ../..
```

## Instalación de BackendRust

Desde la raíz de `WS_PSI`:

```bash
mkdir -p third_party

git clone https://github.com/UO265181/pswoosh_WS_PSI.git

mv pswoosh_WS_PSI third_party/pswoosh
```

A continuación, se compila e instala el módulo nativo:

```bash
cd third_party/pswoosh/rust/ref0

maturin develop --release
```

Para comprobar que la capa FFI funciona correctamente:

```bash
python test_pswoosh_ffi.py
```

Volver a la raíz del proyecto:

```bash
cd ../../../..
```

## Instalación automatizada

También puede utilizarse el script de instalación incluido en el repositorio:

```bash
./setup.sh -pswoosh
```

Este script crea el entorno virtual, instala las dependencias principales y prepara la integración con `pswoosh`.

## Configuración de Firebase

El sistema puede registrar resultados, métricas y actividad en Firebase. Para ello debe colocarse el fichero de credenciales en la raíz del proyecto:

```text
FirebaseCredentials.json
```

Además, debe configurarse la URL de la base de datos en:

```text
Network/collections/DbConstants.py
```

El fichero de credenciales no debe subirse a repositorios públicos.

## Ejecución local

Con el entorno virtual activado, el servicio puede lanzarse con Flask:

```bash
flask --app flaskr:create_app run
```

O mediante Waitress, opción recomendada para pruebas más estables:

```bash
waitress-serve --host 127.0.0.1 --port 8080 --call flaskr:create_app
```

La interfaz web estará disponible en:

```text
http://127.0.0.1:8080/
```

La API REST estará disponible en:

```text
http://127.0.0.1:8080/api
```

## Ejecución con Docker

Desde la raíz del proyecto:

```bash
docker build -t ws-psi .
```

Para levantar los nodos definidos en Docker Compose:

```bash
docker compose up
```

O en segundo plano:

```bash
docker compose up -d
```

Para comprobar los contenedores activos:

```bash
docker ps
```

Para detener el entorno:

```bash
docker compose down
```

Por defecto, Docker Compose levanta varios nodos accesibles desde distintos puertos locales.

## Pruebas

El repositorio incluye pruebas unitarias, pruebas de integración, pruebas de corrección y benchmarks de rendimiento relacionados con SWOOSH.

Ejemplo de prueba unitaria básica:

```bash
export PYTHONPATH=.

python tests/swoosh/unit/python/test_setup_A_python.py
```

Las pruebas y benchmarks principales se encuentran en:

```text
tests/swoosh/
```

## Notas sobre Windows

La instalación en Windows no se ha documentado como procedimiento principal debido a la complejidad adicional de compilar `pswoosh_ffi`. El problema aparece principalmente durante la ejecución de `build.rs`, ya que el proyecto utiliza opciones de compilación orientadas a GCC/Clang que no son compatibles directamente con MSVC.

Por este motivo, se recomienda utilizar Linux para reproducir la instalación completa.

## Repositorios relacionados

- Repositorio principal:  
  `https://github.com/UO265181/WS_PSI`

- Fork adaptado de `pswoosh`:  
  `https://github.com/UO265181/pswoosh_WS_PSI`

## Licencia

Este repositorio mantiene la licencia indicada en el fichero `LICENSE`.

Algunas dependencias externas utilizadas durante el proyecto están sujetas a sus propias licencias, como `python-flint`, `py-fhe`, `PyO3` y `pswoosh`.
