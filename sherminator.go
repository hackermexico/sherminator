package main

import (
    "flag"
    "fmt"
    "net"
    "time"
)

// Puertos característicos de cada SO
var osPorts = map[string][]int{
    "Windows": {135, 139, 445, 3389, 5357, 2179, 5985, 49152, 49153, 49154, 49155, 49156, 49157},
    "Linux":   {22, 25, 53, 80, 111, 137, 139, 443, 631, 2049, 3306, 5432, 6000, 8080},
    "macOS":   {548, 427, 3689, 5000, 62078, 49159, 49160, 49161, 49162, 49163},
    "Android": {5228, 5229, 5230, 8081, 8443, 5353, 2000, 9000, 3838, 10001},
    "iOS":     {62078, 5353, 3689, 3283, 4500, 5000, 49152, 49153},
}

// Iconos por SO
var osIcons = map[string]string{
    "Windows": "🪟",
    "Linux":   "🐧",
    "macOS":   "🍏",
    "Android": "🤖",
    "iOS":     "📱",
}

// Escaneo de un puerto con timeout rápido
func scanPort(host string, port int) bool {
    address := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

// Detección de SO según puertos abiertos
func detectOS(host string) (string, []int) {
    results := make(map[string]int)
    openPorts := []int{}

    for osName, ports := range osPorts {
        for _, port := range ports {
            if scanPort(host, port) {
                results[osName]++
                openPorts = append(openPorts, port)
            }
        }
    }

    // Escoger el SO con más coincidencias
    var probableOS string
    maxMatches := 0
    for osName, count := range results {
        if count > maxMatches {
            maxMatches = count
            probableOS = osName
        }
    }

    return probableOS, openPorts
}

func main() {
    target := flag.String("target", "", "IP o dominio objetivo")
    flag.Parse()

    if *target == "" {
        fmt.Println("Uso: go run sherminator.go -target <IP>")
        return
    }

    fmt.Println("🛡️  Sherminator by OIHEC - OS Detector")
    fmt.Println("--------------------------------------")

    osDetected, ports := detectOS(*target)
    if osDetected != "" {
        fmt.Printf("Posible sistema operativo: %s %s\n", osDetected, osIcons[osDetected])
        fmt.Printf("Puertos abiertos detectados: %v\n", ports)
    } else {
        fmt.Println("No se pudo determinar el sistema operativo con los puertos analizados.")
    }
}

