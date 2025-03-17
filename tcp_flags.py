tcp_flags_dict = {
    "01": "FIN: Finalización de la conexión",
    "02": "SYN: Sincronización para iniciar una conexión",
    "04": "RST: Restablecimiento de la conexión",
    "08": "PSH: Push, los datos deben ser enviados al receptor inmediatamente",
    "10": "ACK: Acknowledgment, confirmación de recepción de paquetes",
    "20": "URG: Urgente, los datos deben ser procesados de inmediato",
    "40": "ECE: ECN-Echo, indica congestión en la red",
    "80": "CWR: Congestion Window Reduced, indica reducción de la ventana de congestión",
    "100": "NS: Nonce Sum, protege contra ataques de inyección de paquetes"
}

# Ejemplo de acceso a un valor
flag = "02"
print(tcp_flags_dict[flag])  # Salida: SYN: Sincronización para iniciar una conexión
