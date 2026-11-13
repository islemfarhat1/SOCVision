import ipaddress


def safe_ip(value) -> str | None:
    """
    Retourne l'adresse IP normalisée, ou None si la valeur n'est pas une IP.

    Les IP viennent des logs (champ data.srcip de Wazuh) : elles sont donc
    contrôlables par un attaquant et doivent être validées avant d'être
    utilisées dans une URL d'API ou dans un prompt LLM.
    """
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None
