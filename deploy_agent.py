import ollama
import paramiko
import os

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
        "3. Incluye SIEMPRE '--test pingall' al final.\n"
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

        comando_final = f"echo {VM_PASSWORD} | sudo -S {comando_mn}"
        print(f"Ejecutando remotamente: sudo {comando_mn}\n")

        stdin, stdout, stderr = ssh.exec_command(comando_final)

        salida = stdout.read().decode()
        error = stderr.read().decode()

        print("--- RESULTADOS DEL PING ---")
        if salida:
            print(salida.strip())
        if error and "[sudo]" not in error:
            print(f"Alertas de Mininet:\n{error.strip()}")
        print("---------------------------")
        print("Red creada, probada y cerrada con éxito.")

    except Exception as e:
        print(f"Error al conectar: {e}")
    finally:
        ssh.close()


if __name__ == "__main__":
    print("=== AGENTE IA PARA MININET (VERSIÓN COMANDOS) ===")
    peticion = input("Describe la red que quieres crear:\n> ")

    comando_generado = generar_comando_mininet(peticion)

    print("\n--- COMANDO GENERADO ---")
    print(f"sudo {comando_generado}")
    print("------------------------\n")

    confirmacion = input("¿Quieres lanzar este comando en la VM? (s/n): ")
    if confirmacion.lower() == "s":
        desplegar_en_vm(comando_generado)
    else:
        print("Operación cancelada.")
