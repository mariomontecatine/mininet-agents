import sys
import os
import re
import time
import ollama

# Parche para que VS Code encuentre la carpeta utils al darle al Play
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import get_ssh_connection, send_tmux_command, capture_tmux_output

VM_PASSWORD = "mininet"
MODEL_NAME = "qwen2.5:3b"


def generate_mininet_command(user_prompt):
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

    ai_command = response["message"]["content"].strip()
    ai_command = ai_command.replace("```bash", "").replace("```", "").strip()
    return ai_command


def deploy_in_vm(mininet_command):
    print("\nConectando a la máquina virtual...")

    try:
        ssh = get_ssh_connection()

        # 1. Limpiar el entorno y ESPERAR a que termine obligatoriamente
        print("Limpiando sesiones anteriores de Mininet...")
        stdin, stdout, stderr = ssh.exec_command(f"echo {VM_PASSWORD} | sudo -S mn -c")
        stdout.channel.recv_exit_status()

        # Matamos el tmux viejo
        ssh.exec_command("tmux kill-session -t sesion_mininet")
        time.sleep(1)

        # 2. Iniciar tmux vacío en segundo plano
        print("Creando sesión de terminal persistente...")
        ssh.exec_command("tmux new-session -d -s sesion_mininet")
        time.sleep(1)

        # 3. Escribir el comando de Mininet SIMULANDO TECLADO REAL
        print(f"Lanzando red: sudo {mininet_command}")
        send_tmux_command(ssh, f"sudo {mininet_command}")
        time.sleep(1)  # Esperamos 1 segundo a que sudo pida la contraseña

        # Enviamos la contraseña simulando que la tecleamos
        send_tmux_command(ssh, VM_PASSWORD)

        # Le damos tiempo a Mininet para que levante los nodos
        print("Esperando a que Mininet construya la red (5 segundos)...")
        time.sleep(5)

        # 4. Enviar el comando pingall a la consola de Mininet
        print("Enviando comando 'pingall'...")
        send_tmux_command(ssh, "pingall")
        time.sleep(5)

        # 4.5. ACTIVACIÓN DE SERVIDORES IPERF (NUEVO)
        print("Activando servidores iperf en todos los nodos...")
        # Capturamos nodos para saber a quién activar
        output_nodes = capture_tmux_output(ssh)
        active_hosts = re.findall(r"\bh\d+\b", output_nodes)

        for host in sorted(list(set(active_hosts))):
            print(f" -> Levantando iperf en {host}")
            send_tmux_command(ssh, f"{host} iperf -s -D")
            time.sleep(0.2)

        # 5. Capturar la salida final
        print("\nCapturando estado final de la terminal...")
        output = capture_tmux_output(ssh)

        print("\n--- RESULTADOS EN LA TERMINAL VIRTUAL ---")
        if output:
            lines = [line for line in output.split("\n") if line.strip()]
            # Mostramos un resumen de las últimas líneas
            print("\n".join(lines[-15:]))
        print("-----------------------------------------")

        print("\nRed desplegada correctamente.")
        print("Todos los hosts tienen el servidor iperf escuchando.")
        print("La sesión está abierta. Puedes verla con: tmux attach -t sesion_mininet")

    except Exception as e:
        print(f"Error en la conexión o ejecución: {e}")
    finally:
        if "ssh" in locals():
            ssh.close()


if __name__ == "__main__":
    print("=== AGENTE IA DE DESPLIEGUE (Mininet AIOps) ===")
    user_request = input(
        "Describe la red que quieres crear (Ej: 'una red en árbol con profundidad 2 y fanout 3'):\n> "
    )

    generated_command = generate_mininet_command(user_request)

    print("\n--- COMANDO GENERADO ---")
    print(f"sudo {generated_command}")
    print("------------------------\n")

    confirmation = input(
        "¿Quieres desplegar esta red de forma persistente en la VM? (s/n): "
    )
    if confirmation.lower() == "s":
        deploy_in_vm(generated_command)
    else:
        print("Operación cancelada.")
