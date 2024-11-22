from colorama import Fore, init
import os

init()

MENU: str = """
Seleccione una opción:

1) Generar llaves RSA
2) Firmar archivo
3) Verificar firma
0) Salir
"""

def start_menu():
    """
    Start the main menu of the application.
    """

    os.system("cls")


    print(Fore.CYAN, "BIENVENIDO AL FIRMADOR Y VERIFICADOR DE FIRMAS")
    print(Fore.MAGENTA, MENU)
    
    selection: int = int(input())

    if selection not in range(0, 4):
        print(Fore.RED, "\nOpción no válida. Vuelve a intentar.\n\n")
        
        os.system("cls")
        start_menu()
    
    elif selection == 1:
        generate_rsa_keys()
    
    elif selection == 2:
        print(Fore.GREEN, "Firmar archivo")
    
    elif selection == 3:
        print(Fore.GREEN, "Verificar firma")
    
    elif selection == 0:
        print(Fore.YELLOW, "\n¡Hasta luego!")
        exit()


def generate_rsa_keys():
    """
    Generate RSA keys.
    """

    os.system("cls")
    
    print(Fore.CYAN, "GENERAR LLAVES RSA")
    
    print(Fore.MAGENTA, "\nIngrese el nombre de la llave privada:")
    private_key: str = input()
    
    print(Fore.MAGENTA, "\nIngrese el nombre de la llave pública:")
    public_key: str = input()
    
    print(Fore.MAGENTA, "\nIngrese el tamaño de la llave (en bits):")
    key_size: int = int(input())

    os.system("cls")
    
    print(Fore.GREEN, "Generando llaves RSA...")
    
    try:
        os.system(f"openssl genrsa -out {private_key} {key_size}")
        os.system(f"openssl rsa -in {private_key} -pubout -out {public_key}")
        
        print(Fore.GREEN, "Llaves generadas con éxito.")
        input("\nPresione Enter para continuar...")

    except Exception as e:
        print(Fore.RED, f"Error al generar las llaves: {e}")
    
    start_menu()


start_menu()