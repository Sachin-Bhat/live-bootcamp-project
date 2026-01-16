## Setup & Building
```bash
cargo install bacon
cd app-service
cargo build
cd ..
cd auth-service
cargo build
cd ..
```

## Run servers locally (Manually)
#### App service
```bash
cd app-service
bacon run
```

visit http://localhost:8000

#### Auth service
```bash
cd auth-service
bacon run
```

visit http://localhost:3000

## Run servers locally (Docker)
```bash
docker compose build
docker compose up
```

visit http://localhost:8000 and http://localhost:3000
