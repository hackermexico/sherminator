import socket
import argparse
import threading
import queue
import json
import sys
import time

# Puertos característicos por SO
OS_PORTS = {
    "Windows": {135, 139, 445, 3389, 5357, 2179, 5985, 49152, 49153, 49154, 49155, 49156, 49157},
    "Linux":   {22, 25, 53, 80, 111, 137, 139, 443, 631, 2049, 3306, 5432, 6000, 8080},
    "macOS":   {548, 427, 3689, 5000, 62078, 49159, 49160, 49161, 49162, 49163},
    "Android": {5228, 5229, 5230, 8081, 8443, 5353, 2000, 9000, 3838, 10001},
    "iOS":     {62078, 5353, 3689, 3283, 4500, 5000, 49152, 49153},
}

OS_ICONS = {
    "Windows": "🪟",
    "Linux":   "🐧",
    "macOS":   "🍏",
    "Android": "🤖",
    "iOS":     "📱",
}

DEFAULT_TIMEOUT = 0.5  # segundos
THREADS = 100          # cantidad de threads para escaneo

def scan_port(host, port, timeout=DEFAULT_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except Exception:
        return False

def worker(host, ports_queue, results, timeout):
    while True:
        port = ports_queue.get()
        if port is None:
            break
        if scan_port(host, port, timeout):
            results.append(port)
        ports_queue.task_done()

def multi_thread_scan(host, ports, timeout=DEFAULT_TIMEOUT):
    ports_queue = queue.Queue()
    results = []
    threads = []

    # Lanzar threads
    for _ in range(min(THREADS, len(ports))):
        t = threading.Thread(target=worker, args=(host, ports_queue, results, timeout))
        t.daemon = True
        t.start()
        threads.append(t)

    # Agregar puertos a la cola
    for port in ports:
        ports_queue.put(port)

    # Esperar que terminen
    ports_queue.join()

    # Parar threads
    for _ in range(len(threads)):
        ports_queue.put(None)
    for t in threads:
        t.join()

    return results

def detect_os(host, timeout=DEFAULT_TIMEOUT):
    all_ports = set()
    for pset in OS_PORTS.values():
        all_ports.update(pset)

    print(f"[*] Escaneando {len(all_ports)} puertos en {host}...")

    open_ports = multi_thread_scan(host, list(all_ports), timeout)

    # Contar coincidencias por SO
    counts = {}
    for os_name, ports in OS_PORTS.items():
        matches = len(set(open_ports) & ports)
        counts[os_name] = matches

    total_found = sum(counts.values())
    if total_found == 0:
        return None, open_ports, counts

    # Porcentaje de coincidencia
    percentages = {os_name: (count / len(ports)) * 100 for os_name, count in counts.items()}

    # SO probable es el que tiene mayor porcentaje
    probable_os = max(percentages, key=percentages.get)

    return probable_os, open_ports, percentages

def print_results(probable_os, open_ports, percentages):
    if probable_os:
        print(f"\n✅ Posible sistema operativo detectado: {probable_os} {OS_ICONS.get(probable_os, '')}")
    else:
        print("\n❌ No se pudo detectar el sistema operativo.")

    print(f"\nPuertos abiertos detectados ({len(open_ports)}): {sorted(open_ports)}")

    print("\nPorcentaje de coincidencia por sistema operativo:")
    for os_name, pct in percentages.items():
        print(f"  - {os_name}: {pct:.2f}%")

def save_json(filename, target, probable_os, open_ports, percentages):
    data = {
        "target": target,
        "detected_os": probable_os,
        "open_ports": sorted(open_ports),
        "percentages": percentages,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n[+] Resultados guardados en {filename}")

def main():
    parser = argparse.ArgumentParser(description="Sherminator OS Detector avanzado - OIHEC")
    parser.add_argument("-t", "--target", required=False, help="IP o dominio objetivo")
    parser.add_argument("-j", "--json", help="Guardar resultados en archivo JSON")
    parser.add_argument("-to", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout por puerto en segundos (default 0.5s)")
    args = parser.parse_args()

    print("🛡️ Sherminator by OIHEC - OS Detector Avanzado\n--------------------------------------------")

    # Modo interactivo si no hay target
    if not args.target:
        args.target = input("Ingresa IP o dominio objetivo: ").strip()

    try:
        probable_os, open_ports, percentages = detect_os(args.target, args.timeout)
        print_results(probable_os, open_ports, percentages)

        if args.json:
            save_json(args.json, args.target, probable_os, open_ports, percentages)

    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por usuario.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
