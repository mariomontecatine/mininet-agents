import os
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


def inicializar_conocimiento():
    embeddings = OllamaEmbeddings(model=EMBEDDING_MODEL)

    if os.path.exists(DB_DIR):
        print("Cargando base de conocimiento existente...")
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
        "3. Incluye '--test pingall'.\n"
        "4. Usa unicamente los parametros que existan en la documentacion proporcionada.\n"
        "5. Devuelve el comando limpio, sin explicaciones ni formato markdown."
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

        print("--- RESULTADOS ---")
        if salida:
            print(salida.strip())
        if error and "[sudo]" not in error:
            print(f"Salida de Mininet:\n{error.strip()}")
        print("------------------")

    except Exception as e:
        print(f"Error al conectar: {e}")
    finally:
        ssh.close()


if __name__ == "__main__":
    print("=== AGENTE RAG PARA MININET ===")
    db = inicializar_conocimiento()

    peticion = input("Describe la red que quieres crear:\n> ")
    comando_generado = generar_comando_experto(db, peticion)

    print("\n--- COMANDO GENERADO ---")
    print(f"sudo {comando_generado}")
    print("------------------------\n")

    confirmacion = input("¿Quieres lanzar este comando en la VM? (s/n): ")
    if confirmacion.lower() == "s":
        desplegar_en_vm(comando_generado)
    else:
        print("Operacion cancelada.")
