import ollama
import paramiko
import os
import time

VM_MOTE = "mininet"
VM_PASSWORD = "mininet"
MODEL_NAME = "qwen2.5:3b"


def generar_comando_mininet(user_prompt):
    print("\nPensando el comando de Mininet...")

    system_prompt = (
        "Eres un experto estricto en redes SDN y Mininet. Genera ÚNICAMENTE el comando de terminal usando 'mn'.\n"
        "REGLAS OBLIGATORIAS:\n"
        "1. NO escribas código Python. Solo el comando bash.\n"
        "2. Empieza directamente con 'mn', NO uses 'sudo'.\n"
        "3. NO uses el flag '--test'. Necesitamos que la red se quede abierta interactiva.\n"
        "4. SOLO puedes usar estas topologías predefinidas EXACTAMENTE con esta sintaxis (NO inventes variables):\n"
        "   - single,N : Un solo switch conectado a N hosts. (Ej: --topo=single,5)\n"
        "   - linear,N,M : N switches conectados en línea, con M hosts conectados a cada switch. (Ej: --topo=linear,2,5 crea 2 switches con 5 hosts cada uno)\n"
        "   - tree,depth=D,fanout=F : Topología en árbol con profundidad D y F ramas por nivel. (Ej: --topo=tree,depth=2,fanout=3)\n"
        "5. Devuelve ÚNICAMENTE el comando, sin bloques de código ```bash y sin texto extra."
    )

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )

    comando_ia = response["message"]["content"].strip()
    comando_ia = comando_ia.replace("```bash", "").replace("```", "").strip()
    return comando_ia


def desplegar_en_vm(comando_mn):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_config = paramiko.SSHConfig()
    config_path = os.path.expanduser("~/.ssh/config")
    if os.path.exists(config_path):
        with open(config_path) as f:
            ssh_config.parse(f)

    host_conf = ssh_config.lookup(VM_MOTE)
    ip_real = host_conf.get("hostname", VM_MOTE)
    usuario = host_conf.get("user", "mininet")

    print(f"\nConectando a '{VM_MOTE}' ({usuario}@{ip_real})...")

    try:
        ssh.connect(hostname=ip_real, username=usuario, password=VM_PASSWORD)

        # 1. Limpiar el entorno y ESPERAR a que termine obligatoriamente
        print(
            "Limpiando sesiones anteriores de Mininet (esto puede tardar un par de segundos)..."
        )
        stdin, stdout, stderr = ssh.exec_command(f"echo {VM_PASSWORD} | sudo -S mn -c")
        stdout.channel.recv_exit_status()  # Bloquea la ejecución hasta que mn -c termine de verdad

        # Matamos el tmux viejo (como usuario normal)
        ssh.exec_command("tmux kill-session -t sesion_mininet")
        time.sleep(1)

        # 2. Iniciar tmux vacío en segundo plano (como usuario normal)
        print("Creando sesión de terminal persistente...")
        ssh.exec_command("tmux new-session -d -s sesion_mininet")
        time.sleep(1)

        # 3. Escribir el comando de Mininet dentro de la sesión
        print(f"Lanzando red: {comando_mn}")
        comando_lanzar = f"tmux send-keys -t sesion_mininet 'echo {VM_PASSWORD} | sudo -S {comando_mn}' C-m"
        ssh.exec_command(comando_lanzar)

        # Le damos tiempo a Mininet para que levante los nodos
        print("Esperando a que Mininet construya la red (5 segundos)...")
        time.sleep(5)

        # 4. Enviar el comando pingall a la consola de Mininet
        print("Enviando comando 'pingall'...")
        ssh.exec_command("tmux send-keys -t sesion_mininet 'pingall' C-m")

        # Esperamos a que termine el pingall
        time.sleep(5)

        # 5. Capturar la salida de la pantalla de tmux
        print("Capturando salida de la terminal...")
        stdin, stdout, stderr = ssh.exec_command("tmux capture-pane -pt sesion_mininet")
        salida = stdout.read().decode()

        print("\n--- RESULTADOS EN LA TERMINAL VIRTUAL ---")
        if salida:
            lineas = [linea for linea in salida.split("\n") if linea.strip()]
            print("\n".join(lineas[-15:]))
        print("-----------------------------------------")

        print("\nRed creada. La sesión ESTÁ ABIERTA.")
        print(
            "Para ver la sesión en la máquina virtual, ejecuta: tmux attach -t sesion_mininet"
        )

    except Exception as e:
        print(f"Error en la conexión o ejecución: {e}")
    finally:
        ssh.close()


if __name__ == "__main__":
    print("=== AGENTE IA PARA MININET (VERSIÓN SESIÓN PERSISTENTE) ===")
    peticion = input("Describe la red que quieres crear:\n> ")

    comando_generado = generar_comando_mininet(peticion)

    print("\n--- COMANDO GENERADO ---")
    print(f"sudo {comando_generado}")
    print("------------------------\n")

    confirmacion = input(
        "¿Quieres desplegar esta red de forma persistente en la VM? (s/n): "
    )
    if confirmacion.lower() == "s":
        desplegar_en_vm(comando_generado)
    else:
        print("Operación cancelada.")
