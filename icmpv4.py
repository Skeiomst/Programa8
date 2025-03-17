icmpv4_dict = {
    "00": {
        "00": "Echo Reply: Respuesta a una solicitud de eco (ping)"
    },
    "03": {
        "00": "Destination Unreachable: Red de destino inalcanzable",
        "01": "Destination Unreachable: Host de destino inalcanzable",
        "02": "Destination Unreachable: Protocolo inalcanzable",
        "03": "Destination Unreachable: Puerto inalcanzable",
        "04": "Destination Unreachable: Fragmentación necesaria y DF (Don’t Fragment) establecido",
        "05": "Destination Unreachable: Ruta de origen fallida",
        "06": "Destination Unreachable: Red de destino desconocida",
        "07": "Destination Unreachable: Host de destino desconocido",
        "08": "Destination Unreachable: Host de origen aislado",
        "09": "Destination Unreachable: Red de destino administrativamente prohibida",
        "0a": "Destination Unreachable: Host de destino administrativamente prohibido",
        "0b": "Destination Unreachable: Red de destino inaccesible para el tipo de servicio",
        "0c": "Destination Unreachable: Host de destino inaccesible para el tipo de servicio",
        "0d": "Destination Unreachable: Comunicación administrativamente prohibida por filtros",
        "0e": "Destination Unreachable: Violación de precedencia de host de destino",
        "0f": "Destination Unreachable: Precedencia de corte en efecto"
    },
    "04": {
        "00": "Source Quench: Reducción de tráfico (obsoleto)"
    },
    "05": {
        "00": "Redirect: Redireccionar datagramas para la red",
        "01": "Redirect: Redireccionar datagramas para el host",
        "02": "Redirect: Redireccionar datagramas para el tipo de servicio y la red",
        "03": "Redirect: Redireccionar datagramas para el tipo de servicio y el host"
    },
    "08": {
        "00": "Echo Request: Solicitud de eco (ping)"
    },
    "09": {
        "00": "Router Advertisement: Anuncio de router",
        "01": "Router Advertisement: Solo este router"
    },
    "0a": {
        "00": "Router Solicitation: Solicitud de router"
    },
    "0b": {
        "00": "Time Exceeded: Tiempo de vida (TTL) excedido en tránsito",
        "01": "Time Exceeded: Tiempo excedido durante la reensamblación del fragmento"
    },
    "0c": {
        "00": "Parameter Problem: Error de puntero",
        "01": "Parameter Problem: Faltan opciones requeridas",
        "02": "Parameter Problem: Longitud de opción incorrecta"
    },
    "0d": {
        "00": "Timestamp: Solicitud de marca de tiempo"
    },
    "0e": {
        "00": "Timestamp Reply: Respuesta de marca de tiempo"
    },
    "0f": {
        "00": "Information Request: Solicitud de información (obsoleto)"
    },
    "10": {
        "00": "Information Reply: Respuesta de información (obsoleto)"
    },
    "11": {
        "00": "Address Mask Request: Solicitud de máscara de dirección (obsoleto)"
    },
    "12": {
        "00": "Address Mask Reply: Respuesta de máscara de dirección (obsoleto)"
    },
    "1e": {
        "00": "Traceroute: Solicitud de rastreo"
    },
    "1f": {
        "00": "Conversion Error: Error de conversión"
    },
    "20": {
        "00": "Mobile Host Redirect: Redirección de host móvil"
    },
    "21": {
        "00": "IPv6 Where-Are-You: ¿Dónde estás? (IPv6)"
    },
    "22": {
        "00": "IPv6 I-Am-Here: Estoy aquí (IPv6)"
    },
    "23": {
        "00": "Mobile Registration Request: Solicitud de registro móvil"
    },
    "24": {
        "00": "Mobile Registration Reply: Respuesta de registro móvil"
    },
    "25": {
        "00": "Domain Name Request: Solicitud de nombre de dominio"
    },
    "26": {
        "00": "Domain Name Reply: Respuesta de nombre de dominio"
    },
    "27": {
        "00": "SKIP: Simple Key-Management for Internet Protocols"
    },
    "28": {
        "00": "Photuris: Solicitud de autenticación"
    }
}

# Ejemplo de acceso a un valor
tipo = "03"
codigo = "0b"
print(icmpv4_dict[tipo][codigo])  # Salida: Destination Unreachable: Comunicación con el destino prohibida debido a restricciones administrativas
