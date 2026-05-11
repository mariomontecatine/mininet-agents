import sys
import os

# Añadir la raíz del proyecto al path para que todos los tests puedan importar
# agents/, utils/ y dashboard/ sin instalar el paquete.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
