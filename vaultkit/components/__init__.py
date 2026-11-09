"""Componentes de software do framework.

Cada subpacote é um componente com:

* ``interfaces.py`` — interface **provida** (contrato público, classe abstrata);
* implementações concretas intercambiáveis;
* dependências declaradas como interfaces **requeridas** (ex.: ``IVaultTransport``),
  injetadas pelo construtor, o que permite reusar o componente fora do framework
  (os microserviços usam os mesmos componentes).

=================  =======================  ==============================
Componente         Interface provida        Interfaces requeridas
=================  =======================  ==============================
auth               IAuthenticator,          IVaultTransport
                   ITokenProvider
secrets            ISecretStore             IVaultTransport, ITokenProvider
cache              ISecretCache             (nenhuma; relógio opcional)
audit              IAuditSink               (nenhuma; HTTP ou SQLite internos)
=================  =======================  ==============================
"""
