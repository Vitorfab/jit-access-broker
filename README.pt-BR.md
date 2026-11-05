# jit-access-broker

Um broker de acesso privilegiado Just-In-Time (JIT), pequeno e bem testado, para um laboratório local
com recursos simulados. O usuário pede acesso elevado com justificativa, aprovadores decidem,
o acesso expira sozinho e todo evento vai para um log de auditoria append-only e resistente a adulteração.

> **Status:** v1.0.0.
> **Projeto de laboratório:** os usuários são simulados (`--as <usuario>`) e não há autenticação real.
> Nunca use para proteger sistemas reais.

## Por que existe
Acesso privilegiado permanente é uma das fraquezas mais exploradas em segurança de identidade.
O JIT resolve isso: o usuário recebe acesso elevado só quando precisa, só pelo tempo necessário,
só depois de um pedido justificado e aprovado, e tudo fica registrado.
Este projeto demonstra o modelo de ponta a ponta: privilégio mínimo, separação de funções,
acesso com prazo, fluxo de aprovação e auditoria.

## Funcionalidades
- Política como código (YAML), validada de forma estrita, com negação por padrão
- Lista de aprovadores e número de aprovações por papel (por exemplo, aprovação por duas pessoas em papéis de alto risco)
- Separação de funções: sem autoaprovação e sem aprovador repetido
- Concessões com prazo; a expiração é verificada no momento da checagem, não por um job em segundo plano
- Revogação e varredura de expiração, somente para admins, e idempotentes
- Log de auditoria JSON Lines append-only com cadeia de hash SHA-256 e `audit verify`
  (texto livre nunca é registrado; tentativas recusadas viram `action_refused`)
- CLI com saída `--json`
- API REST local em 127.0.0.1 com token aleatório

## Instalação
Requer Python 3.11+ e [uv](https://docs.astral.sh/uv/).

    uv sync
    uv run jit-broker --help

## Uso

    uv run jit-broker request --as alice --role db-readonly --minutes 30 --justification "Reading a simulated report"
    uv run jit-broker approve 1 --as carol --reason "Approved"
    uv run jit-broker check --as alice --role db-readonly
    uv run jit-broker grants
    uv run jit-broker revoke 1 --as arthur
    uv run jit-broker sweep --as arthur
    uv run jit-broker audit verify

`check` sai com código 0 quando o acesso é permitido e 1 quando é negado.
O estado fica em `jit-broker.db` e o log em `jit-broker-audit.jsonl` (ambos ignorados pelo git).

### Demo roteirizada (PowerShell)

    .\scripts\demo.ps1

### API local

    uv run jit-broker serve

Escuta somente em `http://127.0.0.1:8765` e mostra um token aleatório. `X-Acting-User` escolhe
um usuário simulado; isso não é autenticação.

## Estrutura do projeto
Veja [docs/architecture.md](docs/architecture.md) (com diagramas Mermaid).
Formato do log: [docs/audit-log-schema.md](docs/audit-log-schema.md).

## Stack
Python, Typer, Pydantic, SQLite, FastAPI, uvicorn, pytest, ruff, mypy, bandit, pip-audit, CodeQL.

## Testes

    uv run pytest

## Notas de segurança
Veja [docs/threat-model.md](docs/threat-model.md), [docs/security-review-v0.2.0.md](docs/security-review-v0.2.0.md)
e [SECURITY.md](SECURITY.md). Limites conhecidos estão documentados.

## Roadmap
v1.1.0: GUI local.

## Licença
MIT. Veja [LICENSE](LICENSE).

## Autor
Vitor Fabelo