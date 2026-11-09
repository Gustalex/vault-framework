"""Hierarquia de erros do framework.

Todo erro que sai do framework é uma subclasse de :class:`VaultKitError`, de modo
que a aplicação pode tratar falhas de cofre sem conhecer o cofre usado.
Nenhuma mensagem de erro carrega token, ``secret_id`` ou valor de segredo.
"""


class VaultKitError(Exception):
    """Erro base do framework."""

    status_code = 500


class ConfigurationError(VaultKitError):
    """Configuração ausente ou inválida (ex.: ``http://`` sem ``allow_http``)."""

    status_code = 500


class InvalidReferenceError(VaultKitError):
    """A referência ao segredo não segue o formato ``[mount:]caminho[#chave][@versão]``."""

    status_code = 400


class AuthenticationError(VaultKitError):
    """O login no cofre falhou (credenciais do AppRole inválidas, token expirado...)."""

    status_code = 401


class PermissionDeniedError(VaultKitError):
    """O token é válido, mas a policy não permite a operação."""

    status_code = 403


class SecretNotFoundError(VaultKitError):
    """O segredo (ou a chave/versão pedida) não existe."""

    status_code = 404


class VaultUnavailableError(VaultKitError):
    """O cofre (ou o gateway) não respondeu: rede, timeout, selado ou erro 5xx."""

    status_code = 503
