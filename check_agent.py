import paramiko
import os
import time

VM_MOTE = "mininet"
VM_PASSWORD = "mininet"


def verificar_sesion():
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

    print(f"Conectando a la sesión existente en {ip_real}...")

    try:
        ssh.connect(hostname=ip_real, username=usuario, password=VM_PASSWORD)

        # Enviamos el comando 'nodes' para ver qué hosts hay
        # Enviamos 'net' para ver las conexiones
        print("Enviando comandos de consulta...")
        ssh.exec_command("tmux send-keys -t sesion_mininet 'nodes' C-m")
        time.sleep(1)
        ssh.exec_command("tmux send-keys -t sesion_mininet 'net' C-m")
        time.sleep(1)

        # Capturamos la pantalla
        stdin, stdout, stderr = ssh.exec_command("tmux capture-pane -pt sesion_mininet")
        salida = stdout.read().decode()

        if salida:
            print("\n--- ESTADO ACTUAL DE LA RED PERSISTENTE ---")
            print(salida)
            print("-------------------------------------------")
        else:
            print("No se recibió respuesta. ¿Está la sesión tmux activa?")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        ssh.close()


if __name__ == "__main__":
    verificar_sesion()
