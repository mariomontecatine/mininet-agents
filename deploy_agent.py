import ollama
import paramiko
import os

VM_MOTE = "mininet"
VM_PASSWORD = "mininet"
MODEL_NAME = "qwen2.5:3b"


def generar_comando_mininet(user_prompt):
    print("\nPensando el comando de Mininet...")

    system_prompt = (
        "Eres un experto en redes SDN y Mininet. El usuario te pedirá una topología. "
        "Tu única tarea es generar el comando de terminal usando 'mn' para desplegarla. "
        "Ejemplo: mn --topo=single,3 --test pingall\n"
        "REGLAS OBLIGATORIAS:\n"
        "1. NO escribas código Python. Genera SOLO el comando de bash.\n"
        "2. NO empieces con 'sudo', empieza directamente con 'mn'.\n"
        "3. Incluye SIEMPRE el parámetro '--test pingall' al final para comprobar la red y que se cierre automáticamente.\n"
        "4. Si el usuario pide un router, asume que se refiere a un switch SDN básico (ej. topo=single,3).\n"
        "5. Devuelve ÚNICAMENTE el comando, sin comillas y sin explicaciones."
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
