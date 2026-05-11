import paramiko
import os
import time

VM_HOST = "mininet"
VM_PASSWORD = "mininet"

# Conexión persistente — se reutiliza entre llamadas para evitar el handshake SSH en cada ciclo
_persistent: paramiko.SSHClient | None = None


def _new_client() -> paramiko.SSHClient:
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
    ssh.get_transport().set_keepalive(30)  # evita que la VM cierre la conexión por inactividad
    return ssh


class _NocloseSSH:
    """
    Proxy sobre SSHClient que convierte .close() en un no-op.
    Permite que el código existente llame a ssh.close() sin cerrar
    la conexión persistente subyacente.
    """

    def __init__(self, client: paramiko.SSHClient):
        self._c = client

    def __getattr__(self, name):
        return getattr(self._c, name)

    def close(self):
        pass  # la conexión real sigue abierta


def get_ssh_connection() -> _NocloseSSH:
    """Devuelve la conexión SSH persistente, reconectando si se cayó."""
    global _persistent
    try:
        t = _persistent and _persistent.get_transport()
        if t and t.is_active():
            return _NocloseSSH(_persistent)
    except Exception:
        pass
    _persistent = _new_client()
    return _NocloseSSH(_persistent)


def close_persistent_connection():
    """Cierra definitivamente la conexión (llamar solo al apagar el sistema)."""
    global _persistent
    if _persistent:
        try:
            _persistent.close()
        except Exception:
            pass
        _persistent = None


def send_tmux_command(ssh, command, session="sesion_mininet"):
    ssh.exec_command(f"tmux send-keys -t {session} '{command}' C-m")


def capture_tmux_output(ssh, session="sesion_mininet"):
    stdin, stdout, stderr = ssh.exec_command(
        f"tmux capture-pane -p -t {session} -S -5000"
    )
    return stdout.read().decode()


def wait_for_mininet_prompt(ssh, timeout=90):
    start_time = time.time()
    while time.time() - start_time < timeout:
        stdin, stdout, stderr = ssh.exec_command(
            "tmux capture-pane -p -t sesion_mininet"
        )
        salida = stdout.read().decode("utf-8").strip()
        lineas = [l for l in salida.split("\n") if l.strip()]
        if lineas and "mininet>" in lineas[-1]:
            return True
        time.sleep(0.1)  # era 0.5 s — 5x más rápido

    print(f"[WARNING] Tiempo máximo ({timeout}s) agotado. ¿Se colgó Mininet?")
    return False
