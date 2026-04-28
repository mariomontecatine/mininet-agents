import paramiko
import os
import time

VM_HOST = "mininet"
VM_PASSWORD = "mininet"


def get_ssh_connection():
    """Establece y devuelve la conexión SSH con la máquina virtual."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_config = paramiko.SSHConfig()
    config_path = os.path.expanduser("~/.ssh/config")

    ip_real = VM_HOST
    usuario = "mininet"

    if os.path.exists(config_path):
        with open(config_path) as f:
            ssh_config.parse(f)
        host_conf = ssh_config.lookup(VM_HOST)
        ip_real = host_conf.get("hostname", VM_HOST)
        usuario = host_conf.get("user", "mininet")

    ssh.connect(hostname=ip_real, username=usuario, password=VM_PASSWORD)
    return ssh


def send_tmux_command(ssh, command, session="sesion_mininet"):
    """Envía un comando a la sesión de tmux en segundo plano."""
    ssh.exec_command(f"tmux send-keys -t {session} '{command}' C-m")


def capture_tmux_output(ssh, session="sesion_mininet"):
    """Captura y devuelve el texto actual de la pantalla de tmux."""
    stdin, stdout, stderr = ssh.exec_command(f"tmux capture-pane -pt {session}")
    return stdout.read().decode()


def wait_for_mininet_prompt(ssh, timeout=60):
    """
    Lee la pantalla continuamente hasta que detecta que Mininet ha terminado
    y vuelve a mostrar el prompt 'mininet>'.
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        output = capture_tmux_output(ssh)

        if output:
            # Separamos en líneas y miramos la última con texto
            lines = [l.strip() for l in output.split("\n") if l.strip()]
            if lines and lines[-1].endswith("mininet>"):
                return True  # ¡El comando ha terminado!

        time.sleep(0.5)  # Hacemos una pausa muy corta antes de volver a mirar

    print(
        f"[WARNING] Tiempo de espera ({timeout}s) agotado. Continuando por seguridad."
    )
    return False
