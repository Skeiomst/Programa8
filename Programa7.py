import tkinter
from tkinter import *
import tkinter as tk
from scapy.all import sniff
from tkinter import Scrollbar, Canvas, Frame, Label
import os
from protocolos import protocolos
from icmpv4 import icmpv4_dict
from icmpv6 import icmpv6_dict
from tcp_flags import tcp_flags_dict
from udp_ports import udp_ports_dict
from scapy.all import sniff
import scapy
indiceActual =0
cadenaBinaria = 0
type_icmp = FALSE
paquetes = []
"""
WireShark
"""

def binario_a_hexadecimal(cadena_binaria): #Funcion para convertir cadenas binarias en hexadecimales
    entero = int.from_bytes(cadena_binaria, byteorder='big')
    hexadecimal = hex(entero)
    return hexadecimal

def extra(cadena):
    resultado_hex = str(cadena)
    
    def tcp():
        puerto_Origen = int(resultado_hex[68:72], 16)
        puerto_Destino = int(resultado_hex[72:76], 16)
        numero_secuencia = int(resultado_hex[76:84], 16)
        numero_acuse = int(resultado_hex[84:92], 16)
        cabecera = resultado_hex[92:94]
        flags = resultado_hex[94:96]
        recepcion = resultado_hex[96:100]
        checksum = resultado_hex[100:104]
        puntero_urgente = resultado_hex[104:108]
        # Formateo de la salida
        imprime_flags = tcp_flags_dict[flags]
        extra = (
            f"\tPuertos:\n\tOrigen: {puerto_Origen}\tDestino: {puerto_Destino}\n\n"
            f"Secuencia: {numero_secuencia}\tAcuse: {numero_acuse}\tCabecera: {cabecera}\nFlags: {flags}\t"
            f"Recepcion: {recepcion}\tChecksum: {checksum}\tPuntero: {puntero_urgente}\n\nMensaje:\n{imprime_flags}"
        )
        return extra
    
    def udp():
        puerto_Origen = int(resultado_hex[68:72], 16)
        puerto_Destino = int(resultado_hex[72:76], 16)
        longitud_Total = int(resultado_hex[76:80], 16)
        checksum = resultado_hex[80:84]
        servicio_origen = str(puerto_Origen)
        servicio_destino = str(puerto_Destino)
        if servicio_destino in udp_ports_dict.keys():
            servicio_puerto = udp_ports_dict[servicio_destino]
            extra = (
                f"\tPuertos:\n\tOrigen: {puerto_Origen}\tDestino: {puerto_Destino}\n"
                f"\tLongitud Total: {longitud_Total}\tchecksum: {checksum}\t\n\n"
                f"\tServicio de Puerto Destino: {servicio_puerto}"
                )
        elif servicio_origen in udp_ports_dict.keys():
            servicio_puerto = udp_ports_dict[servicio_origen]
            extra = (
                f"\tPuertos:\n\tOrigen: {puerto_Origen}\tDestino: {puerto_Destino}\n"
                f"\tLongitud Total: {longitud_Total}\tchecksum: {checksum}\t\n\n"
                f"\tServicio de Puerto Origen: {servicio_puerto}"
                )
        else:
            extra = (
                f"\tPuertos:\n\tOrigen: {puerto_Origen}\tDestino: {puerto_Destino}\n"
                f"\tLongitud Total: {longitud_Total}\tchecksum: {checksum}\t"
                )
        print (f"puerto destino: {puerto_Destino} puerto origen {puerto_Origen}")
        if puerto_Destino == 53 or puerto_Origen == 53:
            identificacion = resultado_hex[84:88]
            flags = resultado_hex[90:94]
            qr = int(flags[0], 16) >> 7  # Primer bit
            opcode = int(flags[0], 16) >> 3 & 0x0F  # Bits del 2 al 5
            aa = int(flags[0], 16) >> 2 & 0x01  # Sexto bit
            tc = int(flags[0], 16) >> 1 & 0x01  # Séptimo bit
            rd = int(flags[0], 16) & 0x01  # Octavo bit
            ra = int(flags[1], 16) >> 7  # Noveno bit
            z = int(flags[1], 16) >> 4 & 0x07  # Bits 10 al 12 (reservados)
            rcode = int(flags[1], 16) & 0x0F  # Bits 13 al 16

            qdcount = resultado_hex[92:96]
            ancount = resultado_hex[96:100]
            nscount = resultado_hex[100:104]
            arcount = resultado_hex[104:108]
            dominio = resultado_hex[108:112]
            tipo = resultado_hex[112:116]
            clase = resultado_hex[116:120]
            ttl = resultado_hex[120:128]
            longitud = resultado_hex[128:132]
            direccion1 = int(resultado_hex[134:134], 16)
            direccion2 = int(resultado_hex[134:136], 16)
            direccion3 = int(resultado_hex[136:138], 16)
            direccion4 = int(resultado_hex[138:140], 16)

            dns = ( f"\tIdentificación: {identificacion}\n" f"\tFlags: {flags}\n" 
                   f"\tQR: {qr}\tOpcode: {opcode}\tAA: {aa}\tTC: {tc}\n\tRD: {rd}\tRA: {ra}\tZ: {z}\tRCODE: {rcode}\n" 
                   f"\tQDCOUNT: {qdcount}\tANCOUNT: {ancount}\n\tNSCOUNT: {nscount}\tARCOUNT: {arcount}\n"
                   f"\n\tRespuesta DNS"
                   f"\nDominio: {dominio}\t Tipo: {tipo}\t Clase: {clase}\n\t TTL: {ttl}\t Longitud: {longitud}"
                   f"\nDireccion ip: {direccion1}.{direccion2}.{direccion3}.{direccion4}"
                   )
            extra = extra + dns
                        
        return extra

  
    def otros():
        extra = ""
        if resultado_hex[24:28] == "0806":
            extra = resultado_hex[68:]
        elif resultado_hex[24:28] == "86dd":
            extra = resultado_hex[108:]
        return extra
    
    if resultado_hex[46:48] == "06":
        imprime_extra = tcp()
    if resultado_hex[46:48] == "11":
        imprime_extra = udp()    
    else:
        imprime_extra = otros()
    
    ventana_Extra = tkinter.Tk()
    ventana_Extra.geometry("400x300")  # Canvas
    ventana_Extra.title("Analisis de paquetes Ethernet")  # Titulo del programa
    ventana_Extra.config(bg="grey")
    label_Extra = Label(ventana_Extra, text="", bg="grey", font=("Arial", 10))
    label_Extra.grid(row=1, column=0, columnspan=3)
    label_Extra.config(text=imprime_extra)
    

def mostrarAlerta(cadena):
    
    def icmpv4():
        resultado_hex = cadena
        tipo_icmp = resultado_hex[68:70]
        codigo_icmp = resultado_hex[70:72]
        tipo = icmpv4_dict[tipo_icmp][codigo_icmp]
        checksum_icmp = resultado_hex[72:76]
        resto_icmp = resultado_hex[76:84]  # Otros datos ICMP (varía dependiendo del tipo y código)
        detalles1 = f"\n\nICMPv4\n\tTipo: {tipo_icmp}\tCódigo: {codigo_icmp}\n\tChecksum ICMP: {checksum_icmp}\tResto ICMP: {resto_icmp}\nMensaje: {tipo}"
        ventana_alerta = tkinter.Tk()
        ventana_alerta.geometry("450x150")  # Canvas
        ventana_alerta.title("Analisis de paquetes Ethernet")  # Titulo del programa
        ventana_alerta.config(bg="grey")
        label_alerta = Label(ventana_alerta, text="", bg="grey", font=("Arial", 10))
        label_alerta.grid(row=1, column=0, columnspan=3)
        label_alerta.config(text=detalles1)
    def icmpv6():
            resultado_hex = cadena
            tipo_icmpv6 = resultado_hex[108:110]
            codigo_icmpv6 = resultado_hex[110:112]
            checksum_icmpv6 = resultado_hex[112:116]
            datos_icmpv6 = resultado_hex[116:148]
            mensaje = icmpv6_dict[tipo_icmpv6][codigo_icmpv6]
            detalles1 = f"\n\nICMPv6\n\tTipo: {tipo_icmpv6}\tCódigo: {codigo_icmpv6}\n\tChecksum ICMP: {checksum_icmpv6}\tResto ICMP: {datos_icmpv6}\nMensaje: {mensaje}"
            ventana_alerta = tkinter.Tk()
            ventana_alerta.geometry("450x150")  # Canvas
            ventana_alerta.title("Analisis de paquetes Ethernet")  # Titulo del programa
            ventana_alerta.config(bg="grey")
            label_alerta = Label(ventana_alerta, text="", bg="grey", font=("Arial", 10))
            label_alerta.grid(row=1, column=0, columnspan=3)
            label_alerta.config(text=detalles1)
    if type_icmp == False: #Si es falso imprime icmpv4 y si es verdadero imprime icmpv6
        icmpv4()
    else:
        icmpv6()

def imprimirIpv4(resultado_hex):
    global type_icmp
    versionIPv4 = resultado_hex[28:30]
    servicio = resultado_hex[30:32]
    longitudTotal = resultado_hex[32:36]
    identificador = resultado_hex[36:40]
    flags = resultado_hex[40:44]
    tiempoVida = resultado_hex[44:46]
    protocolo = resultado_hex[46:48]
    checksum = resultado_hex[48:52]
    #Aqui se convierten 1 bytes a su equivalente en ip: ejemplo ac : 127
    ipv4Origen = str(int(resultado_hex[52:54], 16)) + "." + str(int(resultado_hex[54:56], 16)) + "." + str(int(resultado_hex[56:58], 16)) + "." + str(int(resultado_hex[58:60], 16))
    ipv4Destino = str(int(resultado_hex[60:62], 16)) + "." + str(int(resultado_hex[62:64], 16)) + "." + str(int(resultado_hex[64:66], 16)) + "." + str(int(resultado_hex[66:68], 16))
    detalles = f"Version: {versionIPv4}\tServicio: {servicio}\nLongitud Total:{longitudTotal}\nIdentificador: {identificador}\tFlags: {flags}\nTiempo de vida: {tiempoVida}\nProtocolo: {protocolo}\tChecksum: {checksum}\nDireccion de origen: {ipv4Origen}\nDireccion de destino: {ipv4Destino}\n\n"
    if resultado_hex[46:48] == "01" and resultado_hex[24:28] == "0800":
        boton_alerta.config(state = NORMAL) 
        type_icmp = False
    else:
        boton_alerta.config(state = DISABLED)
    return detalles 


def imprimirArp (resultado_hex):
    tipoHardware = resultado_hex[28:32]
    protocolo = resultado_hex[32:36]
    longitudDireccionHardware = resultado_hex [36:38]
    longitudDireccionProtocolo = resultado_hex[38:40]
    operacion = resultado_hex[40:44]
    direccionHardware = resultado_hex[44:56]
    direccionProtocolo = str(int(resultado_hex[56:58], 16)) + "." + str(int(resultado_hex[58:60],16)) + "." + str(int(resultado_hex[60:62], 16)) + "." + str(int(resultado_hex[62:64],16))  
    direccionHardwareOpjetivo = resultado_hex[64:76]
    direccionProtocoloObjetivo = str(int(resultado_hex[76:78], 16)) + "." + str(int(resultado_hex[78:80], 16)) + "." + str(int(resultado_hex[80:82], 16)) + "." + str(int(resultado_hex[82:84], 16))
    detalles = f"Hardware: {tipoHardware}\tProtocolo: {protocolo}\nLHardware:{longitudDireccionHardware}\tLProtocolo: {longitudDireccionProtocolo}\tOperacion: {operacion}\nDireccion MAC: {direccionHardware}\nDireccion protocolo: {direccionProtocolo}\nHardware objetivo: {direccionHardwareOpjetivo}\nDireccion ip objetivo: {direccionProtocoloObjetivo}\n\n"
    boton_alerta.config(state = DISABLED)
    return detalles




def imprimeIPV6 (resultado_hex): 
    global type_icmp
    version = resultado_hex[28:29]
    trafico = resultado_hex[29:31]
    flujo = resultado_hex [31:36]
    cargaUtil= resultado_hex[36:40]
    encabezadoSiguiente = resultado_hex[40:42]
    saltoLimite = resultado_hex[42:44]
    direccionOrigen = resultado_hex[44:76] 
    direccionDestino = resultado_hex[76:108]
    detalles = f"Version: {version}\tClase detrafico: {trafico}\netiqueta de flujo:{flujo}\nTam carga: {cargaUtil}\tEncabezado: {encabezadoSiguiente}\tSalto: {saltoLimite}\nDireccion de origen IPv6: {direccionOrigen}\nDireccion de destino IPv6: {direccionDestino}\n\n"
    if resultado_hex[40:42] == "3a":
        boton_alerta.config(state = NORMAL) 
        type_icmp = True
        print(encabezadoSiguiente)
    else:
        boton_alerta.config(state = DISABLED)
    return detalles 


def siguientesDetalles():
    global indiceActual
    indiceActual += 1
    return mostrarDetalles() 

def anterioresDetalles():
    global indiceActual
    indiceActual -= 1
    return mostrarDetalles() 

def mostrarDetalles(): #Analisis de los campos de IPv4
    global indiceActual
    numero_archivo = int(entry_numero_archivo.get()) 
    numero_archivo = numero_archivo + indiceActual
    detallesCompletos =""
    
    for i  in range(3): 
        resultado_hex =paquetes[numero_archivo + i-1]
        if resultado_hex[24:28] == "0806":
            print(f"resultado hex: {resultado_hex[26:30]}")
            detalles = imprimirArp(resultado_hex)
            detallesCompletos = detallesCompletos + str(detalles)
                
        elif resultado_hex[24:28] == "86dd":
            detalles = imprimeIPV6(resultado_hex)
            detallesCompletos = detallesCompletos + str(detalles)

        else:     
            detalles = imprimirIpv4(resultado_hex)
            detallesCompletos = detallesCompletos + str (detalles)
            print(f"resultado hex:1 {resultado_hex[24:28]}")

        
        label_detalles.config(text=detallesCompletos)

import tkinter as tk
from scapy.all import sniff
from tkinter import Scrollbar, Canvas, Frame, Label, Entry, Button

# Crear la interfaz gráfica
ventana = tk.Tk()
ventana.geometry("800x650")
ventana.title("Análisis de paquetes Ethernet")
ventana.config(bg="grey")

scroll = Scrollbar(ventana)
canvas = Canvas(ventana, width=440, height=300, yscrollcommand=scroll.set)
scroll.config(command=canvas.yview)
scroll.pack(side="right", fill="y")
canvas.pack(side="left", fill="both", expand=True)

frame = Frame(canvas)
canvas.create_window((0, 0), window=frame, anchor="nw")

# Encabezados de la tabla
encabezados = ["No.", "Destino", "Origen", "Protocolo"]
for j, encabezado in enumerate(encabezados):
    etiqueta = Label(frame, text=encabezado, font=("Arial", 10, "bold"))
    etiqueta.grid(row=0, column=j, padx=10, pady=5)

frame_detalles = Frame(ventana, bg="grey", width=500)
frame_detalles.pack(side="right", fill="y", padx=10, pady=10)

label_numero_archivo = Label(frame_detalles, text="Ip a analizar:", bg="grey", font=("Arial", 10))
label_numero_archivo.grid(row=0, column=0, padx=5)

entry_numero_archivo = Entry(frame_detalles, font=("Arial", 10))
entry_numero_archivo.grid(row=1, column=0, padx=5)

boton_mostrar = Button(frame_detalles, text="Mostrar detalles", command=mostrarDetalles, font=("Arial", 10))
boton_mostrar.grid(row=1, column=1, padx=5)

label_detalles = Label(frame_detalles, text="", bg="grey", font=("Arial", 10))
label_detalles.grid(row=2, column=0, columnspan=3, pady=10)

boton_anterior = Button(frame_detalles, text="<-", command=anterioresDetalles, font=("Arial", 10), width=10)
boton_anterior.grid(row=3, column=0, padx=5, pady=5)

boton_siguiente = Button(frame_detalles, text="->", command=siguientesDetalles, font=("Arial", 10), width=10)
boton_siguiente.grid(row=3, column=1, padx=5, pady=5)

boton_alerta = Button(frame_detalles, text="Alerta", font=("Arial", 10), width=10, command=lambda: mostrarAlerta(cadenaBinaria))
boton_alerta.grid(row=4, column=0, padx=5)
boton_alerta.config(state=tk.DISABLED)

boton_Extra = Button(frame_detalles, text="Extras", font=("Arial", 10), width=10, command=lambda: extra(cadenaBinaria))
boton_Extra.grid(row=4, column=1, padx=5)


# Inicializar la lista de paquetes
paquetes = []
paquetesOriginal = []

def bytes_to_hex(data):
    return "".join(f"{byte:02x}" for byte in data)

def packet_callback(packet):
    # Obtener datos en bruto del paquete
    raw_data = bytes(packet)  # Cadena en bytes

    # Convertir los datos a formato hexadecimal
    hex_data = bytes_to_hex(raw_data)

    # Agregar el paquete en formato hexadecimal a la lista global
    paquetes.append(hex_data)
    paquetesOriginal.append(packet)

def imprimeIp():
    global paquetes 

    # Captura paquetes en tiempo real (ajusta la interfaz según tu sistema)
    sniff(prn=packet_callback, iface="Ethernet", count=30)  # Cambia "Wi-Fi" por tu interfaz

    i = len(paquetes) - 30  # Inicia en el índice correcto
    for paquete in paquetes[-30:]:  # Solo los últimos 30 paquetes capturados
        direccionDestino = paquete[0:12]  # Corregido para mostrar 12 dígitos
        direccionOrigen = paquete[12:24]  # Corregido para mostrar 12 dígitos
        direccionProtocolo = paquete[24:28]
        protocoloImprimir = protocolos.get(direccionProtocolo, "Desconocido")
        datos = [i+1, direccionDestino, direccionOrigen, protocoloImprimir]

        # Asignar los datos en una tabla
        for j, dato in enumerate(datos):
            etiqueta = Label(frame, text=dato, font=("Arial", 10))
            etiqueta.grid(row=i+1, column=j, padx=10, pady=5)
        i += 1
    frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))
    print(f"paquetes {paquetes}")
# Botón para capturar nuevos paquetes

def guardar_paquetes_segmentados(paquetes, nombre_archivo="paquetes_segmentados.txt"):
    """
    Procesa una lista de paquetes, segmenta sus campos y los guarda en un archivo de texto.

    Args:
        paquetes (list): Lista de paquetes capturados previamente.
        nombre_archivo (str): Nombre del archivo donde se guardarán los paquetes segmentados.
    """
    with open(nombre_archivo, "w") as archivo:
        archivo.write("Segmentación de Paquetes:\n")
        archivo.write("=" * 60 + "\n")

        for i, paquete in enumerate(paquetes):
            archivo.write(f"Paquete {i + 1}:\n")
            # Extraer los campos del paquete
            campos = paquete.show(dump=True)  # Representación legible de los campos
            archivo.write(campos)
            archivo.write("\n" + "-" * 60 + "\n")

    print(f"Paquetes segmentados guardados en '{nombre_archivo}'.")

    # Abrir el archivo después de guardarlo
    os.startfile(nombre_archivo)

boton_capturar = Button(frame_detalles, text="Capturar ", command=imprimeIp, font=("Arial", 10))
boton_capturar.grid(row=5, column=0, padx=5)

boton_guardar = Button(frame_detalles, text="Guardar", command=lambda: guardar_paquetes_segmentados(paquetesOriginal), font=("Arial", 10))
boton_guardar.grid(row=5, column=1, padx=5)
imprimeIp()
ventana.mainloop()
