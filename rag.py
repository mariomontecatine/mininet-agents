import os
import json
import time
import paramiko
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_classic.chains import create_retrieval_chain
from langchain_classic.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate

VM_MOTE = "mininet"
VM_PASSWORD = "mininet"
MODEL_NAME = "qwen2.5:3b"
EMBEDDING_MODEL = "nomic-embed-text"
DB_DIR = "./chroma_db"
CACHE_FILE = "memoria_agente.json"


def cargar_memoria():
    """Carga los comandos que ya sabemos que funcionan."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}


def guardar_en_memoria(peticion, comando):
    """Guarda un comando validado para no tener que volver a pensarlo."""
    memoria = cargar_memoria()
    memoria[peticion] = comando
    with open(CACHE_FILE, "w") as f:
        json.dump(memoria, f, indent=4)
    print("✓ Comando guardado en la memoria a largo plazo.")


def inicializar_conocimiento():
    embeddings = OllamaEmbeddings(model=EMBEDDING_MODEL)

    if os.path.exists(DB_DIR):
        print("Cargando base de conocimiento RAG existente...")
        vectorstore = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)
        return vectorstore

    print("Procesando la documentacion de Mininet por primera vez...")
    docs = []

    if os.path.exists("./mininet-docs-wiki"):
        loader_wiki = DirectoryLoader(
            "./mininet-docs-wiki",
            glob="**/*.md",
            loader_cls=TextLoader,
            silent_errors=True,
        )
        docs.extend(loader_wiki.load())

    if os.path.exists("./mininet-repo/examples"):
        loader_ejemplos = DirectoryLoader(
            "./mininet-repo/examples",
            glob="**/*.py",
            loader_cls=TextLoader,
            silent_errors=True,
        )
        docs.extend(loader_ejemplos.load())

    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    splits = text_splitter.split_documents(docs)

    vectorstore = Chroma.from_documents(
        documents=splits, embedding=embeddings, persist_directory=DB_DIR
    )
    return vectorstore


def generar_comando_experto(vectorstore, user_prompt):
    print("\nConsultando la documentacion oficial y pensando...")

    llm = ChatOllama(model=MODEL_NAME)
    retriever = vectorstore.as_retriever(search_kwargs={"k": 4})

    system_prompt = (
        "Eres un ingeniero experto en Mininet. Usa la siguiente documentacion oficial para responder.\n\n"
        "DOCUMENTACION:\n{context}\n\n"
        "REGLAS:\n"
        "1. Genera SOLO el comando de bash empezando por 'mn' para desplegar la red que pide el usuario.\n"
        "2. No uses 'sudo'.\n"
        "3. NO inventes parametros. Los parametros correctos suelen ser en singular (ej: --switch, --controller, --mac). NUNCA uses --switches o --controllers.\n"
        "4. Devuelve el comando limpio, sin explicaciones ni formato markdown."
    )

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            ("human", "{input}"),
        ]
    )

    question_answer_chain = create_stuff_documents_chain(llm, prompt)
    rag_chain = create_retrieval_chain(retriever, question_answer_chain)

    response = rag_chain.invoke({"input": user_prompt})
    comando_ia = response["answer"].strip()
    comando_ia = comando_ia.replace("```bash", "").replace("```", "").strip()

    return comando_ia


def desplegar_en_vm(comando_mn):
    """
    Despliega la red usando Paramiko, instala screen si falta,
    lo deja en segundo plano y verifica si ha sobrevivido.
    """
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

    print(f"\nConectando a '{VM_MOTE}' ({usuario}@{ip_real}) de forma automática...")

    try:
        ssh.connect(hostname=ip_real, username=usuario, password=VM_PASSWORD)

        # 1. Instalar screen si no está (no verás nada, lo hace por debajo)
        ssh.exec_command(
            f"echo {VM_PASSWORD} | sudo -S apt-get install -y screen > /dev/null 2>&1"
        )

        # 2. Matar cualquier sesión vieja que se llame red_mininet por si acaso
        ssh.exec_command(
            f"echo {VM_PASSWORD} | sudo -S screen -S red_mininet -X quit > /dev/null 2>&1"
        )

        # 3. Lanzar Mininet dentro de screen en modo "Detached" (-dmS)
        comando_final = (
            f"echo {VM_PASSWORD} | sudo -S screen -dmS red_mininet {comando_mn}"
        )
        print(f"Lanzando red en segundo plano...")
        ssh.exec_command(comando_final)

        # 4. Esperamos 2 segundos y comprobamos si el proceso 'mn' sigue existiendo
        time.sleep(2)
        stdin, stdout, stderr = ssh.exec_command("pgrep -f '^mn '")
        proceso_vivo = stdout.read().decode().strip()

        print("\n" + "=" * 50)
        if proceso_vivo:
            print("✅ ¡ÉXITO! La topología está viva y corriendo en segundo plano.")
            print("Tus otros agentes ya pueden interactuar con ella.")
            print(
                "\nSi quieres verla tú manualmente en la pantalla de tu Máquina Virtual:"
            )
            print("👉 Entra a la VM y escribe:  sudo screen -r red_mininet")
            print("👉 Para salir de ahí sin matarla pulsa:  Ctrl+A y luego la tecla D")
            print("=" * 50 + "\n")
            return True
        else:
            print(
                "❌ ERROR: Mininet intentó arrancar pero se cerró (probablemente el comando de la IA era inválido)."
            )
            print(f"Comando que falló: {comando_mn}")
            print("=" * 50 + "\n")
            return False

    except Exception as e:
        print(f"Error en la conexión SSH: {e}")
        return False
    finally:
        ssh.close()


if __name__ == "__main__":
    print("=== AGENTE RAG PARA MININET ===")

    # 1. Cargamos el RAG y la memoria (caché)
    db = inicializar_conocimiento()
    memoria = cargar_memoria()

    peticion = input("Describe la red que quieres crear:\n> ")
    es_nuevo = False

    # 2. Verificamos si ya sabemos la respuesta
    if peticion in memoria:
        print("\nRecuperando comando validado de la memoria...")
        comando_generado = memoria[peticion]
    else:
        comando_generado = generar_comando_experto(db, peticion)
        es_nuevo = True

    print("\n--- COMANDO GENERADO ---")
    print(f"sudo {comando_generado}")
    print("------------------------\n")

    confirmacion = input("¿Quieres lanzar este comando en la VM? (s/n): ")

    # 3. Ejecutamos y comprobamos
    if confirmacion.lower() == "s":
        ejecucion_correcta = desplegar_en_vm(comando_generado)

        # Si la red no se ha crasheado y es un comando nuevo, lo guardamos
        if es_nuevo and ejecucion_correcta:
            validar = input(
                "¿Quieres que el agente guarde este comando en su memoria para el futuro? (s/n): "
            )
            if validar.lower() == "s":
                guardar_en_memoria(peticion, comando_generado)
    else:
        print("Operacion cancelada.")
