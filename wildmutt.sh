#!/bin/bash
# Wildmutt v2.0 - Advanced JavaScript Secret Scanner
# By: [Seu Nome]
# Desc: Scans for exposed secrets in JavaScript files with enhanced capabilities

# Configurações
USER_AGENT="Wildmutt/2.0 (Secret Scanner)"
TIMEOUT=15
PATTERNS_FILE="wildmutt_patterns.txt"
DEFAULT_PATTERNS="api[_-]?key|aws[_-]?secret|password|token|secret|ftp|db|sql|oauth|credential|access[_-]?key|auth[_-]?key|client[_-]?secret|encryption[_-]?key|private[_-]?key"
MAX_THREADS=10
CRAWL_DEPTH=1

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Variáveis globais
declare -a JS_URLS
declare -A VISITED_URLS

show_banner() {
    echo -e "${CYAN}"
    echo " __      __.__              __               __   "
    echo "/  \    /  \__|____________/  |_ __ _______ |  |  "
    echo "\   \/\/   /  \___   /\   \   __\  |  \__  \|  |  "
    echo " \        /|  |/    /  \   |  | |  |  // __ \|  |__"
    echo "  \__/\  / |__/_____ \  \  |__| |____/(____  /____/"
    echo "       \/           \/   \/                \/      "
    echo -e "${NC}"
    echo -e "${YELLOW}Wildmutt v2.0 - JavaScript Secret Hunter${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
}

help() {
    echo -e "${GREEN}Uso:${NC}"
    echo "  $0 -u https://target.com [opções]"
    echo
    echo -e "${YELLOW}Opções:${NC}"
    echo "  -u  URL alvo (obrigatório)"
    echo "  -w  Wordlist para descobrir arquivos JS (opcional)"
    echo "  -p  Arquivo com padrões personalizados (padrão: wildmutt_patterns.txt)"
    echo "  -o  Salvar resultados em arquivo (opcional)"
    echo "  -t  Número de threads (padrão: 10)"
    echo "  -d  Profundidade de crawling (padrão: 1)"
    echo "  -c  Verificar validade de chaves encontradas (experimental)"
    echo "  -v  Modo verboso"
    echo "  -h  Mostrar esta ajuda"
    exit 0
}

check_dependencies() {
    local deps=("curl" "grep" "sort" "sed" "awk")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo -e "${RED}[-] Erro: Comando '$dep' não encontrado.${NC}"
            exit 1
        fi
    done
}

init_patterns() {
    if [ -f "$PATTERNS_FILE" ]; then
        echo -e "${GREEN}[+] Usando padrões personalizados: $PATTERNS_FILE${NC}"
    else
        echo -e "${YELLOW}[!] Arquivo de padrões não encontrado. Usando padrões internos${NC}"
        echo "$DEFAULT_PATTERNS" > "$PATTERNS_FILE"
    fi
}

fetch_url() {
    curl -s -A "$USER_AGENT" --max-time "$TIMEOUT" -L "$1" 2>/dev/null
}

get_status() {
    curl -s -o /dev/null -w "%{http_code}" -A "$USER_AGENT" --max-time "$TIMEOUT" -L "$1" 2>/dev/null
}

scan_js() {
    local url=$1
    local content
    local matches
    
    content=$(fetch_url "$url")
    [ -z "$content" ] && return
    
    matches=$(echo "$content" | grep -E -i -f "$PATTERNS_FILE")
    
    if [ -n "$matches" ]; then
        echo -e "\n${GREEN}[!] Segredos encontrados em: ${url}${NC}"
        echo "$matches" | awk '!seen[$0]++'
        
        if [ "$CHECK_VALIDITY" = true ]; then
            validate_secrets "$matches" "$url"
        fi
        
        if [ -n "$OUTPUT_FILE" ]; then
            {
                echo "=== $url ==="
                echo "$matches"
                echo "=== FIM ==="
                echo
            } >> "$OUTPUT_FILE"
        fi
    elif [ "$VERBOSE" = true ]; then
        echo -e "${YELLOW}[+] Arquivo limpo: ${url}${NC}"
    fi
}

validate_secrets() {
    local secrets=$1
    local url=$2
    
    while IFS= read -r secret; do
        # Verificar padrões comuns
        if [[ $secret =~ [a-fA-F0-9]{32} ]]; then
            echo -e "${BLUE}[*] Possível MD5/Hash encontrado: ${secret:0:40}...${NC}"
        fi
        
        if [[ $secret =~ sk_live_[0-9a-zA-Z]{24} ]]; then
            echo -e "${RED}[!] ATENÇÃO: Possível chave privada do Stripe encontrada${NC}"
        fi
        
        if [[ $secret =~ AKIA[0-9A-Z]{16} ]]; then
            echo -e "${RED}[!] ATENÇÃO: Possível AWS Access Key encontrada${NC}"
        fi
    done <<< "$secrets"
}

discover_resources() {
    local url=$1
    local depth=$2
    local content
    
    [ "$depth" -gt "$CRAWL_DEPTH" ] && return
    [ -n "${VISITED_URLS[$url]}" ] && return
    VISITED_URLS["$url"]=1

    echo -e "${YELLOW}[*] Crawling: $url (Profundidade $depth)${NC}"
    content=$(fetch_url "$url")
    [ -z "$content" ] && return

    # Encontrar novos recursos
    mapfile -t new_urls < <(echo "$content" | grep -oP '(?:(src|href)=")[^"]+\.(js|json)(?=")' | sed 's/^src="//;s/^href="//' | sort -u)
    
    for new_url in "${new_urls[@]}"; do
        # Converter URL relativa
        if [[ ! "$new_url" =~ ^https?:// ]]; then
            new_url="${url%/}/$new_url"
        fi
        
        # Adicionar à lista se for JS e não visitado
        if [[ "$new_url" =~ \.(js|json)$ ]] && [ -z "${VISITED_URLS[$new_url]}" ]; then
            JS_URLS+=("$new_url")
            discover_resources "$new_url" $((depth + 1))
        fi
    done
}

main() {
    check_dependencies
    init_patterns
    
    # Coletar JS inicial
    discover_resources "$TARGET_URL" 0
    
    # Wordlist discovery
    if [ -n "$WORDLIST" ]; then
        echo -e "${YELLOW}[*] Testando wordlist: $WORDLIST${NC}"
        while read -r path; do
            # Construir URL
            if [[ "$path" == /* ]]; then
                test_url="${TARGET_URL%/}$path"
            else
                test_url="${TARGET_URL%/}/$path"
            fi
            
            # Verificar se já foi processado
            [ -n "${VISITED_URLS[$test_url]}" ] && continue
            
            # Verificar existência
            status=$(get_status "$test_url")
            if [ "$status" -eq 200 ]; then
                JS_URLS+=("$test_url")
                echo -e "${GREEN}[+] Novo recurso encontrado: $test_url${NC}"
                discover_resources "$test_url" 0
            fi
        done < "$WORDLIST"
    fi
    
    # Processar URLs
    local count=0
    echo -e "${GREEN}[+] Total de recursos para escanear: ${#JS_URLS[@]}${NC}"
    
    for js_url in "${JS_URLS[@]}"; do
        if [ "$VERBOSE" = true ]; then
            echo -e "${YELLOW}[*] Analisando: $js_url${NC}"
        fi
        
        scan_js "$js_url" &
        ((count++))
        
        # Controle de threads
        if ((count % MAX_THREADS == 0)); then
            wait
        fi
    done
    wait
}

# Inicialização
show_banner
while getopts "u:w:p:o:t:d:c:vh" opt; do
    case $opt in
        u) TARGET_URL="$OPTARG";;
        w) WORDLIST="$OPTARG";;
        p) PATTERNS_FILE="$OPTARG";;
        o) OUTPUT_FILE="$OPTARG";;
        t) MAX_THREADS="$OPTARG";;
        d) CRAWL_DEPTH="$OPTARG";;
        c) CHECK_VALIDITY=true;;
        v) VERBOSE=true;;
        h) help;;
        *) exit 1;;
    esac
done

[ -z "$TARGET_URL" ] && help
[ -n "$OUTPUT_FILE" ] && : > "$OUTPUT_FILE"

# Iniciar processo
main
echo -e "${GREEN}[+] Escaneamento completo!${NC}"
