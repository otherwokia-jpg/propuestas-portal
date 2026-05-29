Propuestas Portal — Gestión de Propuestas Técnicas
===================================================

Puerto: 9200
URL: https://datacenter.hubmultiteck.io/propuestas/
Auth: SSO vía Landing (JWT HS256) - mismo que DUNOSUSA
Roles: superadmin, admin, propuestas_admin, propuestas_editor, propuestas_viewer
Base: SQLite (propuestas.db)
Stack: Flask + SQLAlchemy + Docker

Directorios:
  app.py             — Aplicación principal
  templates/         — Jinja2 templates
  uploads/           — Documentos subidos
  Dockerfile         — Imagen Docker
  docker-compose.yml — Orquestación

Comandos:
  docker-compose up -d         — Iniciar
  docker-compose down          — Detener
  docker logs -f propuestas-portal — Ver logs

Seed:
  El seed ejecuta automáticamente al iniciar si la BD está vacía.
  Crea cliente DUNOSUSA y [Cliente MiniMaster] con propuestas y documentos.

Para agregar /propuestas/* en Cloudflare:
  Configurar ruta: datacenter.hubmultiteck.io  /propuestas/*  →  localhost:9200

Para agregar permiso en Landing:
  En login(): allowed_portals.append('propuestas') para roles autorizados.
